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

    res.status(status).json(data);
}


function getBearerToken(req) {

    const header =
        req.headers.authorization || "";

    if (
        !header.startsWith("Bearer ")
    ) {
        return null;
    }

    return header.substring(7);
}


async function getAdminProfile(req) {

    const token =
        getBearerToken(req);

    if (!token) {
        return null;
    }


    /*
     * Benutzer anhand des normalen
     * Access Tokens feststellen.
     */

    const {
        data: userData,
        error: userError
    } =
        await supabaseAdmin.auth.getUser(
            token
        );


    if (
        userError ||
        !userData.user
    ) {
        return null;
    }


    /*
     * Prüfen, ob dieser Benutzer
     * tatsächlich aktiver Admin ist.
     */

    const {
        data: profile,
        error: profileError
    } =
        await supabaseAdmin
            .from("profiles")
            .select(
                "id, role, active"
            )
            .eq(
                "id",
                userData.user.id
            )
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


module.exports = async function handler(
    req,
    res
) {

    /*
     * Nur POST erlauben
     */

    if (
        req.method !== "POST"
    ) {

        return json(
            res,
            405,
            {
                error:
                    "Methode nicht erlaubt."
            }
        );
    }


    /*
     * Admin authentifizieren
     */

    const admin =
        await getAdminProfile(req);


    if (!admin) {

        return json(
            res,
            401,
            {
                error:
                    "Keine Administratorberechtigung."
            }
        );
    }


    const body =
        req.body || {};

    const action =
        body.action;


    /* ============================================================
       MITARBEITER ANLEGEN
    ============================================================ */

    if (
        action ===
        "create_employee"
    ) {

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

            return json(
                res,
                400,
                {
                    error:
                        "Bitte alle Pflichtfelder ausfüllen."
                }
            );
        }


        if (
            password.length < 8
        ) {

            return json(
                res,
                400,
                {
                    error:
                        "Das Passwort muss mindestens 8 Zeichen lang sein."
                }
            );
        }


        const employeeRole =
            role === "admin"
                ? "admin"
                : "employee";


        /*
         * Prüfen, ob Mitarbeiternummer
         * bereits existiert.
         */

        const {
            data: existingEmployee
        } =
            await supabaseAdmin
                .from("profiles")
                .select("id")
                .eq(
                    "employee_number",
                    employee_number
                )
                .maybeSingle();


        if (existingEmployee) {

            return json(
                res,
                409,
                {
                    error:
                        "Diese Mitarbeiternummer existiert bereits."
                }
            );
        }


        /*
         * Supabase Auth Benutzer anlegen
         */

        const {
            data: authData,
            error: authError
        } =
            await supabaseAdmin.auth.admin.createUser({

                email:
                    email.trim(),

                password:
                    password,

                email_confirm:
                    true
            });


        if (authError) {

            return json(
                res,
                400,
                {
                    error:
                        authError.message
                }
            );
        }


        const userId =
            authData.user.id;


        /*
         * Profil anlegen
         */

        const {
            data: profile,
            error: profileError
        } =
            await supabaseAdmin
                .from("profiles")
                .insert({

                    id:
                        userId,

                    employee_number:
                        employee_number.trim(),

                    first_name:
                        first_name.trim(),

                    last_name:
                        last_name.trim(),

                    role:
                        employeeRole,

                    active:
                        true
                })
                .select()
                .single();


        /*
         * Falls das Profil nicht erstellt
         * werden konnte, Auth-Benutzer wieder
         * löschen.
         */

        if (profileError) {

            await supabaseAdmin.auth.admin.deleteUser(
                userId
            );


            return json(
                res,
                400,
                {
                    error:
                        "Mitarbeiterprofil konnte nicht erstellt werden."
                }
            );
        }


        /*
         * Audit Log
         */

        await supabaseAdmin
            .from("audit_logs")
            .insert({

                user_id:
                    admin.user.id,

                action:
                    "employee_created",

                entity_type:
                    "profiles",

                entity_id:
                    userId,

                new_data: {
                    employee_number,
                    first_name,
                    last_name,
                    role: employeeRole
                }
            });


        return json(
            res,
            200,
            {
                success: true,
                employee: profile
            }
        );
    }


    /* ============================================================
       PASSWORT ZURÜCKSETZEN
    ============================================================ */

    if (
        action ===
        "reset_password"
    ) {

        const {
            user_id,
            password
        } = body;


        if (
            !user_id ||
            !password
        ) {

            return json(
                res,
                400,
                {
                    error:
                        "Benutzer und neues Passwort sind erforderlich."
                }
            );
        }


        if (
            password.length < 8
        ) {

            return json(
                res,
                400,
                {
                    error:
                        "Das Passwort muss mindestens 8 Zeichen lang sein."
                }
            );
        }


        /*
         * Eigenes Admin-Passwort nicht
         * über diese Funktion ändern.
         */

        if (
            user_id ===
            admin.user.id
        ) {

            return json(
                res,
                400,
                {
                    error:
                        "Das eigene Administratorpasswort bitte über den normalen Passwortwechsel ändern."
                }
            );
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
                .eq(
                    "id",
                    user_id
                )
                .single();


        if (
            targetError ||
            !targetProfile
        ) {

            return json(
                res,
                404,
                {
                    error:
                        "Mitarbeiter nicht gefunden."
                }
            );
        }


        /*
         * Auth-Passwort ändern
         */

        const {
            error: passwordError
        } =
            await supabaseAdmin.auth.admin.updateUserById(
                user_id,
                {
                    password
                }
            );


        if (passwordError) {

            return json(
                res,
                400,
                {
                    error:
                        passwordError.message
                }
            );
        }


        /*
         * Audit Log
         *
         * Niemals das Passwort speichern.
         */

        await supabaseAdmin
            .from("audit_logs")
            .insert({

                user_id:
                    admin.user.id,

                action:
                    "employee_password_reset",

                entity_type:
                    "profiles",

                entity_id:
                    user_id,

                new_data: {
                    employee_number:
                        targetProfile.employee_number
                }
            });


        return json(
            res,
            200,
            {
                success: true
            }
        );
    }


    /* ============================================================
       UNBEKANNTE AKTION
    ============================================================ */

    return json(
        res,
        400,
        {
            error:
                "Unbekannte Aktion."
        }
    );
};
