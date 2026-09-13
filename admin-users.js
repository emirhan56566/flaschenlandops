const { createClient } = require("@supabase/supabase-js");

const supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY,
    {
        auth: {
            autoRefreshToken: false,
            persistSession: false
        }
    }
);

function json(res, status, data) {
    return res.status(status).json(data);
}

function getBearerToken(req) {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
        return null;
    }

    return header.substring(7);
}

async function getAdminProfile(req) {
    const token = getBearerToken(req);

    if (!token) {
        return null;
    }

    const {
        data: userData,
        error: userError
    } = await supabaseAdmin.auth.getUser(token);

    if (userError || !userData.user) {
        return null;
    }

    const {
        data: profile,
        error: profileError
    } = await supabaseAdmin
        .from("profiles")
        .select("id, employee_number, first_name, last_name, role, active")
        .eq("id", userData.user.id)
        .single();

    if (
        profileError ||
        !profile ||
        profile.role !== "admin" ||
        !profile.active
    ) {
        return null;
    }

    return {
        user: userData.user,
        profile
    };
}

async function writeAudit({
    userId,
    action,
    entityType,
    entityId,
    oldData = null,
    newData = null
}) {
    await supabaseAdmin
        .from("audit_logs")
        .insert({
            user_id: userId,
            action,
            entity_type: entityType,
            entity_id: entityId,
            old_data: oldData,
            new_data: newData
        });
}

module.exports = async function handler(req, res) {
    if (req.method !== "POST") {
        return json(res, 405, {
            error: "Methode nicht erlaubt."
        });
    }

    const admin = await getAdminProfile(req);

    if (!admin) {
        return json(res, 401, {
            error: "Keine Administratorberechtigung."
        });
    }

    const body = req.body || {};
    const action = body.action;

    /*
     * ---------------------------------------------------------
     * MITARBEITER ANLEGEN
     * ---------------------------------------------------------
     */
    if (action === "create_employee") {
        const {
            email,
            password,
            employee_number,
            first_name,
            last_name,
            role
        } = body;

        if (
            !email ||
            !password ||
            !employee_number ||
            !first_name ||
            !last_name
        ) {
            return json(res, 400, {
                error: "Bitte alle Pflichtfelder ausfüllen."
            });
        }

        if (password.length < 8) {
            return json(res, 400, {
                error: "Das Passwort muss mindestens 8 Zeichen lang sein."
            });
        }

        const employeeRole =
            role === "admin"
                ? "admin"
                : "employee";

        const cleanEmail = String(email).trim();
        const cleanEmployeeNumber = String(employee_number).trim();
        const cleanFirstName = String(first_name).trim();
        const cleanLastName = String(last_name).trim();

        if (
            !cleanEmail ||
            !cleanEmployeeNumber ||
            !cleanFirstName ||
            !cleanLastName
        ) {
            return json(res, 400, {
                error: "Bitte alle Pflichtfelder ausfüllen."
            });
        }

        const {
            data: existingEmployee
        } = await supabaseAdmin
            .from("profiles")
            .select("id")
            .eq("employee_number", cleanEmployeeNumber)
            .maybeSingle();

        if (existingEmployee) {
            return json(res, 409, {
                error: "Diese Mitarbeiternummer existiert bereits."
            });
        }

        const {
            data: authData,
            error: authError
        } = await supabaseAdmin.auth.admin.createUser({
            email: cleanEmail,
            password,
            email_confirm: true
        });

        if (authError || !authData.user) {
            return json(res, 400, {
                error: authError?.message || "Benutzer konnte nicht erstellt werden."
            });
        }

        const userId = authData.user.id;

        const {
            data: profile,
            error: profileError
        } = await supabaseAdmin
            .from("profiles")
            .insert({
                id: userId,
                employee_number: cleanEmployeeNumber,
                first_name: cleanFirstName,
                last_name: cleanLastName,
                role: employeeRole,
                active: true
            })
            .select()
            .single();

        if (profileError) {
            await supabaseAdmin.auth.admin.deleteUser(userId);

            return json(res, 400, {
                error: "Mitarbeiterprofil konnte nicht erstellt werden."
            });
        }

        await writeAudit({
            userId: admin.user.id,
            action: "employee_created",
            entityType: "profiles",
            entityId: userId,
            newData: {
                employee_number: cleanEmployeeNumber,
                first_name: cleanFirstName,
                last_name: cleanLastName,
                role: employeeRole,
                active: true
            }
        });

        return json(res, 200, {
            success: true,
            employee: profile
        });
    }

    /*
     * ---------------------------------------------------------
     * MITARBEITER BEARBEITEN
     * ---------------------------------------------------------
     */
    if (action === "update_employee") {
        const {
            user_id,
            employee_number,
            first_name,
            last_name,
            role
        } = body;

        if (
            !user_id ||
            !employee_number ||
            !first_name ||
            !last_name
        ) {
            return json(res, 400, {
                error: "Bitte alle Pflichtfelder ausfüllen."
            });
        }

        const cleanEmployeeNumber = String(employee_number).trim();
        const cleanFirstName = String(first_name).trim();
        const cleanLastName = String(last_name).trim();

        if (
            !cleanEmployeeNumber ||
            !cleanFirstName ||
            !cleanLastName
        ) {
            return json(res, 400, {
                error: "Bitte alle Pflichtfelder ausfüllen."
            });
        }

        const {
            data: targetProfile,
            error: targetError
        } = await supabaseAdmin
            .from("profiles")
            .select(
                "id, employee_number, first_name, last_name, role, active"
            )
            .eq("id", user_id)
            .single();

        if (targetError || !targetProfile) {
            return json(res, 404, {
                error: "Mitarbeiter nicht gefunden."
            });
        }

        const newRole =
            role === "admin"
                ? "admin"
                : "employee";

        /*
         * Der aktuell eingeloggte Admin darf sich nicht selbst
         * die Administratorrolle entziehen.
         */
        if (
            user_id === admin.user.id &&
            newRole !== "admin"
        ) {
            return json(res, 400, {
                error:
                    "Die eigene Administratorrolle kann hier nicht entfernt werden."
            });
        }

        const {
            data: duplicateEmployee
        } = await supabaseAdmin
            .from("profiles")
            .select("id")
            .eq("employee_number", cleanEmployeeNumber)
            .neq("id", user_id)
            .maybeSingle();

        if (duplicateEmployee) {
            return json(res, 409, {
                error: "Diese Mitarbeiternummer wird bereits verwendet."
            });
        }

        const newData = {
            employee_number: cleanEmployeeNumber,
            first_name: cleanFirstName,
            last_name: cleanLastName,
            role: newRole
        };

        const {
            data: updatedProfile,
            error: updateError
        } = await supabaseAdmin
            .from("profiles")
            .update(newData)
            .eq("id", user_id)
            .select()
            .single();

        if (updateError) {
            return json(res, 400, {
                error: "Mitarbeiter konnte nicht aktualisiert werden."
            });
        }

        await writeAudit({
            userId: admin.user.id,
            action: "employee_updated",
            entityType: "profiles",
            entityId: user_id,
            oldData: {
                employee_number: targetProfile.employee_number,
                first_name: targetProfile.first_name,
                last_name: targetProfile.last_name,
                role: targetProfile.role,
                active: targetProfile.active
            },
            newData: {
                employee_number: updatedProfile.employee_number,
                first_name: updatedProfile.first_name,
                last_name: updatedProfile.last_name,
                role: updatedProfile.role,
                active: updatedProfile.active
            }
        });

        return json(res, 200, {
            success: true,
            employee: updatedProfile
        });
    }

    /*
     * ---------------------------------------------------------
     * MITARBEITER AKTIVIEREN / DEAKTIVIEREN
     * ---------------------------------------------------------
     */
    if (action === "toggle_employee") {
        const {
            user_id,
            active
        } = body;

        if (!user_id || typeof active !== "boolean") {
            return json(res, 400, {
                error: "Ungültige Mitarbeiterdaten."
            });
        }

        /*
         * Ein Admin darf sich nicht selbst deaktivieren.
         */
        if (
            user_id === admin.user.id &&
            active === false
        ) {
            return json(res, 400, {
                error:
                    "Der aktuell angemeldete Administrator kann nicht deaktiviert werden."
            });
        }

        const {
            data: targetProfile,
            error: targetError
        } = await supabaseAdmin
            .from("profiles")
            .select(
                "id, employee_number, first_name, last_name, role, active"
            )
            .eq("id", user_id)
            .single();

        if (targetError || !targetProfile) {
            return json(res, 404, {
                error: "Mitarbeiter nicht gefunden."
            });
        }

        /*
         * Bei Deaktivierung wird eine eventuell laufende
         * Arbeitssitzung beendet.
         */
        if (!active) {
            const now = new Date().toISOString();

            await supabaseAdmin
                .from("work_sessions")
                .update({
                    ended_at: now
                })
                .eq("employee_id", user_id)
                .is("ended_at", null);
        }

        const {
            data: updatedProfile,
            error: updateError
        } = await supabaseAdmin
            .from("profiles")
            .update({
                active
            })
            .eq("id", user_id)
            .select()
            .single();

        if (updateError) {
            return json(res, 400, {
                error: "Mitarbeiterstatus konnte nicht geändert werden."
            });
        }

        await writeAudit({
            userId: admin.user.id,
            action: active
                ? "employee_activated"
                : "employee_deactivated",
            entityType: "profiles",
            entityId: user_id,
            oldData: {
                active: targetProfile.active
            },
            newData: {
                active: updatedProfile.active
            }
        });

        return json(res, 200, {
            success: true,
            employee: updatedProfile
        });
    }

    /*
     * ---------------------------------------------------------
     * PASSWORT ZURÜCKSETZEN
     * ---------------------------------------------------------
     */
    if (action === "reset_password") {
        const {
            user_id,
            password
        } = body;

        if (!user_id || !password) {
            return json(res, 400, {
                error: "Benutzer und neues Passwort sind erforderlich."
            });
        }

        if (password.length < 8) {
            return json(res, 400, {
                error: "Das Passwort muss mindestens 8 Zeichen lang sein."
            });
        }

        if (user_id === admin.user.id) {
            return json(res, 400, {
                error:
                    "Das eigene Administratorpasswort bitte über den normalen Passwortwechsel ändern."
            });
        }

        const {
            data: targetProfile,
            error: targetError
        } = await supabaseAdmin
            .from("profiles")
            .select(
                "id, employee_number, first_name, last_name, role, active"
            )
            .eq("id", user_id)
            .single();

        if (targetError || !targetProfile) {
            return json(res, 404, {
                error: "Mitarbeiter nicht gefunden."
            });
        }

        const {
            error: passwordError
        } = await supabaseAdmin.auth.admin.updateUserById(
            user_id,
            {
                password
            }
        );

        if (passwordError) {
            return json(res, 400, {
                error: passwordError.message
            });
        }

        await writeAudit({
            userId: admin.user.id,
            action: "employee_password_reset",
            entityType: "profiles",
            entityId: user_id,
            newData: {
                employee_number: targetProfile.employee_number
            }
        });

        return json(res, 200, {
            success: true
        });
    }

    return json(res, 400, {
        error: "Unbekannte Aktion."
    });
};