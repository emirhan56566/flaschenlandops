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

    if (
        userError ||
        !userData ||
        !userData.user
    ) {
        return null;
    }

    const {
        data: profile,
        error: profileError
    } = await supabaseAdmin
        .from("profiles")
        .select(
            "id, employee_number, first_name, last_name, role, active"
        )
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

function cleanString(value) {
    return typeof value === "string"
        ? value.trim()
        : "";
}

function validRole(role) {
    return role === "admin" || role === "employee";
}

async function writeAudit(
    adminUserId,
    action,
    entityId,
    oldData = null,
    newData = null
) {
    await supabaseAdmin
        .from("audit_logs")
        .insert({
            user_id: adminUserId,
            action,
            entity_type: "profiles",
            entity_id: String(entityId),
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

    try {

        const admin = await getAdminProfile(req);

        if (!admin) {
            return json(res, 401, {
                error:
                    "Keine Administratorberechtigung."
            });
        }

        const body = req.body || {};
        const action = body.action;

        /*
         * ========================================================
         * MITARBEITER ERSTELLEN
         * ========================================================
         */

        if (action === "create_employee") {

            const email =
                cleanString(body.email);

            const password =
                typeof body.password === "string"
                    ? body.password
                    : "";

            const employeeNumber =
                cleanString(
                    body.employee_number
                );

            const firstName =
                cleanString(
                    body.first_name
                );

            const lastName =
                cleanString(
                    body.last_name
                );

            const role =
                validRole(body.role)
                    ? body.role
                    : "employee";

            if (
                !email ||
                !password ||
                !employeeNumber ||
                !firstName ||
                !lastName
            ) {
                return json(res, 400, {
                    error:
                        "Bitte alle Pflichtfelder ausfüllen."
                });
            }

            if (password.length < 8) {
                return json(res, 400, {
                    error:
                        "Das Passwort muss mindestens 8 Zeichen lang sein."
                });
            }

            const {
                data: existingEmployee,
                error: existingError
            } = await supabaseAdmin
                .from("profiles")
                .select("id")
                .eq(
                    "employee_number",
                    employeeNumber
                )
                .maybeSingle();

            if (existingError) {
                return json(res, 500, {
                    error:
                        "Mitarbeiter konnte nicht geprüft werden."
                });
            }

            if (existingEmployee) {
                return json(res, 409, {
                    error:
                        "Diese Mitarbeiternummer existiert bereits."
                });
            }

            const {
                data: existingEmail
            } = await supabaseAdmin
                .from("profiles")
                .select("id")
                .eq(
                    "id",
                    admin.user.id
                )
                .maybeSingle();

            /*
             * Supabase Auth prüft die E-Mail-Adresse.
             */

            const {
                data: authData,
                error: authError
            } =
                await supabaseAdmin.auth.admin.createUser({
                    email,
                    password,
                    email_confirm: true
                });

            if (authError) {
                return json(res, 400, {
                    error:
                        authError.message
                });
            }

            const userId =
                authData.user.id;

            const {
                data: profile,
                error: profileError
            } =
                await supabaseAdmin
                    .from("profiles")
                    .insert({
                        id: userId,
                        employee_number:
                            employeeNumber,
                        first_name:
                            firstName,
                        last_name:
                            lastName,
                        role,
                        active: true
                    })
                    .select()
                    .single();

            if (profileError) {

                await supabaseAdmin.auth.admin.deleteUser(
                    userId
                );

                return json(res, 400, {
                    error:
                        "Mitarbeiterprofil konnte nicht erstellt werden."
                });
            }

            await writeAudit(
                admin.user.id,
                "employee_created",
                userId,
                null,
                {
                    employee_number:
                        employeeNumber,
                    first_name:
                        firstName,
                    last_name:
                        lastName,
                    role
                }
            );

            return json(res, 200, {
                success: true,
                employee: profile
            });
        }


        /*
         * ========================================================
         * MITARBEITER BEARBEITEN
         * ========================================================
         */

        if (action === "update_employee") {

            const userId =
                cleanString(
                    body.user_id
                );

            if (!userId) {
                return json(res, 400, {
                    error:
                        "Mitarbeiter-ID fehlt."
                });
            }

            const {
                data: existing,
                error: existingError
            } =
                await supabaseAdmin
                    .from("profiles")
                    .select(
                        "id, employee_number, first_name, last_name, role, active"
                    )
                    .eq("id", userId)
                    .single();

            if (
                existingError ||
                !existing
            ) {
                return json(res, 404, {
                    error:
                        "Mitarbeiter nicht gefunden."
                });
            }

            const employeeNumber =
                cleanString(
                    body.employee_number
                );

            const firstName =
                cleanString(
                    body.first_name
                );

            const lastName =
                cleanString(
                    body.last_name
                );

            const role =
                body.role !== undefined
                    ? body.role
                    : existing.role;

            if (
                !employeeNumber ||
                !firstName ||
                !lastName ||
                !validRole(role)
            ) {
                return json(res, 400, {
                    error:
                        "Ungültige Mitarbeiterdaten."
                });
            }

            /*
             * Selbstschutz:
             * Ein Admin darf sich hier nicht selbst
             * zum Mitarbeiter machen.
             */

            if (
                userId === admin.user.id &&
                role !== "admin"
            ) {
                return json(res, 400, {
                    error:
                        "Das eigene Administratorkonto kann hier nicht auf Mitarbeiter geändert werden."
                });
            }

            /*
             * Mitarbeiternummer darf nicht doppelt sein.
             */

            const {
                data: duplicate
            } =
                await supabaseAdmin
                    .from("profiles")
                    .select("id")
                    .eq(
                        "employee_number",
                        employeeNumber
                    )
                    .neq(
                        "id",
                        userId
                    )
                    .maybeSingle();

            if (duplicate) {
                return json(res, 409, {
                    error:
                        "Diese Mitarbeiternummer wird bereits verwendet."
                });
            }

            const {
                data: updated,
                error: updateError
            } =
                await supabaseAdmin
                    .from("profiles")
                    .update({
                        employee_number:
                            employeeNumber,
                        first_name:
                            firstName,
                        last_name:
                            lastName,
                        role,
                        updated_at:
                            new Date().toISOString()
                    })
                    .eq("id", userId)
                    .select()
                    .single();

            if (updateError) {
                return json(res, 400, {
                    error:
                        updateError.message
                });
            }

            await writeAudit(
                admin.user.id,
                "employee_updated",
                userId,
                {
                    employee_number:
                        existing.employee_number,
                    first_name:
                        existing.first_name,
                    last_name:
                        existing.last_name,
                    role:
                        existing.role,
                    active:
                        existing.active
                },
                {
                    employee_number:
                        updated.employee_number,
                    first_name:
                        updated.first_name,
                    last_name:
                        updated.last_name,
                    role:
                        updated.role,
                    active:
                        updated.active
                }
            );

            return json(res, 200, {
                success: true,
                employee: updated
            });
        }


        /*
         * ========================================================
         * AKTIVIEREN / DEAKTIVIEREN
         * ========================================================
         */

        if (action === "toggle_employee") {

            const userId =
                cleanString(
                    body.user_id
                );

            if (!userId) {
                return json(res, 400, {
                    error:
                        "Mitarbeiter-ID fehlt."
                });
            }

            if (
                userId === admin.user.id
            ) {
                return json(res, 400, {
                    error:
                        "Das eigene Administratorkonto kann hier nicht deaktiviert werden."
                });
            }

            const {
                data: existing,
                error: existingError
            } =
                await supabaseAdmin
                    .from("profiles")
                    .select(
                        "id, employee_number, first_name, last_name, role, active"
                    )
                    .eq("id", userId)
                    .single();

            if (
                existingError ||
                !existing
            ) {
                return json(res, 404, {
                    error:
                        "Mitarbeiter nicht gefunden."
                });
            }

            const newStatus =
                !existing.active;

            const {
                data: updated,
                error: updateError
            } =
                await supabaseAdmin
                    .from("profiles")
                    .update({
                        active:
                            newStatus,
                        updated_at:
                            new Date().toISOString()
                    })
                    .eq("id", userId)
                    .select()
                    .single();

            if (updateError) {
                return json(res, 400, {
                    error:
                        updateError.message
                });
            }

            await writeAudit(
                admin.user.id,
                newStatus
                    ? "employee_activated"
                    : "employee_deactivated",
                userId,
                {
                    active:
                        existing.active
                },
                {
                    active:
                        updated.active
                }
            );

            return json(res, 200, {
                success: true,
                employee: updated
            });
        }


        /*
         * ========================================================
         * PASSWORT ZURÜCKSETZEN
         * ========================================================
         */

        if (action === "reset_password") {

            const userId =
                cleanString(
                    body.user_id
                );

            const password =
                typeof body.password === "string"
                    ? body.password
                    : "";

            if (
                !userId ||
                !password
            ) {
                return json(res, 400, {
                    error:
                        "Benutzer und neues Passwort sind erforderlich."
                });
            }

            if (password.length < 8) {
                return json(res, 400, {
                    error:
                        "Das Passwort muss mindestens 8 Zeichen lang sein."
                });
            }

            if (
                userId === admin.user.id
            ) {
                return json(res, 400, {
                    error:
                        "Das eigene Administratorpasswort bitte über den normalen Passwortwechsel ändern."
                });
            }

            const {
                data: targetProfile,
                error: targetError
            } =
                await supabaseAdmin
                    .from("profiles")
                    .select(
                        "id, employee_number, first_name, last_name"
                    )
                    .eq("id", userId)
                    .single();

            if (
                targetError ||
                !targetProfile
            ) {
                return json(res, 404, {
                    error:
                        "Mitarbeiter nicht gefunden."
                });
            }

            const {
                error: passwordError
            } =
                await supabaseAdmin.auth.admin.updateUserById(
                    userId,
                    {
                        password
                    }
                );

            if (passwordError) {
                return json(res, 400, {
                    error:
                        passwordError.message
                });
            }

            await writeAudit(
                admin.user.id,
                "employee_password_reset",
                userId,
                null,
                {
                    employee_number:
                        targetProfile.employee_number
                }
            );

            return json(res, 200, {
                success: true
            });
        }


        /*
         * ========================================================
         * UNBEKANNTE AKTION
         * ========================================================
         */

        return json(res, 400, {
            error:
                "Unbekannte Aktion."
        });

    } catch (error) {

        console.error(
            "Admin API Fehler:",
            error
        );

        return json(res, 500, {
            error:
                "Interner Serverfehler."
        });
    }
};