-- Identity Vessel Authentication Schema
-- Organizations and Users for username/password authentication

-- Organizations table
DEFINE TABLE organizations SCHEMAFULL;
DEFINE FIELD name ON organizations TYPE string;
DEFINE FIELD created_at ON organizations TYPE datetime DEFAULT time::now();
DEFINE INDEX org_name ON organizations FIELDS name UNIQUE;

-- Users table
DEFINE TABLE users SCHEMAFULL;
DEFINE FIELD email ON users TYPE string;
DEFINE FIELD password_hash ON users TYPE string;
DEFINE FIELD name ON users TYPE string;
DEFINE FIELD org_id ON users TYPE record<organizations>;
DEFINE FIELD created_at ON users TYPE datetime DEFAULT time::now();
DEFINE INDEX user_email ON users FIELDS email UNIQUE;

-- Bootstrap test organization and user for development
LET $metabob_org = (SELECT * FROM organizations WHERE name = 'Metabob' LIMIT 1);
IF $metabob_org == [] THEN
  CREATE organizations:metabob_com SET
    name = 'Metabob',
    created_at = time::now();
END;

LET $avi_user = (SELECT * FROM users WHERE email = 'avi@metabob.com' LIMIT 1);
IF $avi_user == [] THEN
  CREATE users:avi SET
    email = 'avi@metabob.com',
    password_hash = crypto::argon2::generate('password123'),
    name = 'Avi',
    org_id = organizations:metabob_com,
    created_at = time::now();
END;
