-- Schema dump generated from burtgel.db (structure only, no data)

CREATE TABLE admin_document_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL UNIQUE,
            display_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

CREATE TABLE admin_document_category_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL UNIQUE,
            category_id INTEGER REFERENCES admin_document_categories(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

CREATE TABLE admin_document_subfiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_file_name TEXT NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            uploaded_at TEXT NOT NULL
        );

CREATE TABLE app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        );

CREATE TABLE assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            department_id INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
            asset_name TEXT NOT NULL,
            description TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            asset_group_code TEXT NOT NULL,
            has_personal_data TEXT NOT NULL,
            has_sensitive_data TEXT NOT NULL,
            owner TEXT NOT NULL,
            custodian TEXT NOT NULL,
            location TEXT NOT NULL,
            access_right TEXT NOT NULL DEFAULT '',
            retention_period TEXT NOT NULL DEFAULT '',
            confidentiality TEXT NOT NULL DEFAULT '',
            integrity_impact TEXT NOT NULL DEFAULT '',
            availability_impact TEXT NOT NULL DEFAULT '',
            asset_value TEXT NOT NULL DEFAULT '',
            asset_category TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        , review_frequency TEXT NOT NULL DEFAULT '');

CREATE TABLE attachment_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_number TEXT NOT NULL DEFAULT '',
            request_type TEXT NOT NULL DEFAULT '',
            change_summary TEXT NOT NULL DEFAULT '',
            request_date TEXT NOT NULL DEFAULT '',
            requester_name TEXT NOT NULL DEFAULT '',
            related_asset_number TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT '',
            priority TEXT NOT NULL DEFAULT '',
            planned_implementation_date TEXT NOT NULL DEFAULT '',
            actual_implementation_date TEXT NOT NULL DEFAULT '',
            decision TEXT NOT NULL DEFAULT '',
            decision_reason TEXT NOT NULL DEFAULT '',
            decision_date TEXT NOT NULL DEFAULT '',
            decision_unit TEXT NOT NULL DEFAULT '',
            change_implemented_date TEXT NOT NULL DEFAULT '',
            change_verified_date TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

CREATE TABLE attachment_disposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            disposal_date TEXT NOT NULL DEFAULT '',
            asset_name TEXT NOT NULL DEFAULT '',
            information_classification TEXT NOT NULL DEFAULT '',
            location_system TEXT NOT NULL DEFAULT '',
            disposal_method TEXT NOT NULL DEFAULT '',
            disposal_basis TEXT NOT NULL DEFAULT '',
            executor_name TEXT NOT NULL DEFAULT '',
            approved_by TEXT NOT NULL DEFAULT '',
            act_number TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

CREATE TABLE attachment_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL DEFAULT '',
            detected_date TEXT NOT NULL DEFAULT '',
            occurred_date TEXT NOT NULL DEFAULT '',
            reported_by TEXT NOT NULL DEFAULT '',
            system_location TEXT NOT NULL DEFAULT '',
            incident_type TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT '',
            l1_started TEXT NOT NULL DEFAULT '',
            l2 TEXT NOT NULL DEFAULT '',
            l3 TEXT NOT NULL DEFAULT '',
            closed TEXT NOT NULL DEFAULT '',
            resolution_time TEXT NOT NULL DEFAULT '',
            sla_violated TEXT NOT NULL DEFAULT '',
            root_cause TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

CREATE TABLE audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        , actor_name TEXT);

CREATE TABLE audit_logs_2026_03 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT,
        details TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    );

CREATE TABLE audit_logs_2026_04 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT,
        details TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    );

CREATE TABLE audit_logs_2026_05 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT,
        details TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    , actor_name TEXT);

CREATE TABLE audit_logs_2026_06 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            actor_name TEXT,
            target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );

CREATE TABLE audit_logs_2026_07 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            actor_name TEXT,
            target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );

CREATE TABLE auth_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            token_type TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

CREATE TABLE custom_register_brief_columns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            register_id INTEGER NOT NULL REFERENCES custom_registers(id) ON DELETE CASCADE,
            column_id INTEGER NOT NULL REFERENCES custom_register_columns(id) ON DELETE CASCADE,
            UNIQUE(register_id, column_id)
        );

CREATE TABLE custom_register_cells (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            row_id INTEGER NOT NULL REFERENCES custom_register_rows(id) ON DELETE CASCADE,
            column_id INTEGER NOT NULL REFERENCES custom_register_columns(id) ON DELETE CASCADE,
            value TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(row_id, column_id)
        );

CREATE TABLE custom_register_columns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            register_id INTEGER NOT NULL REFERENCES custom_registers(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            slug TEXT NOT NULL,
            display_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(register_id, slug)
        );

CREATE TABLE custom_register_rows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            register_id INTEGER NOT NULL REFERENCES custom_registers(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

CREATE TABLE custom_registers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

CREATE TABLE department_brief_columns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            department_id INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
            field_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(department_id, field_name)
        );

CREATE TABLE department_column_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            department_id INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
            field_name TEXT NOT NULL,
            can_edit INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(department_id, field_name)
        );

CREATE TABLE departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            slug TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL
        );

CREATE TABLE kpi_directories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

CREATE TABLE kpi_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            directory_id INTEGER NOT NULL REFERENCES kpi_directories(id) ON DELETE CASCADE,
            order_num INTEGER NOT NULL DEFAULT 0,
            indicator TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            formula TEXT NOT NULL DEFAULT '',
            target_level TEXT NOT NULL DEFAULT '',
            frequency TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        , due_date TEXT NOT NULL DEFAULT '');

CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL
        , last_active_at TEXT);

CREATE TABLE sqlite_sequence(name,seq);

CREATE TABLE user_department_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            department_id INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
            can_read INTEGER NOT NULL DEFAULT 0,
            can_update INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, department_id)
        );

CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        , last_login_at TEXT, must_change_password INTEGER NOT NULL DEFAULT 0, password_changed_at TEXT, email TEXT, display_name TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT 'user', last_invited_at TEXT);

