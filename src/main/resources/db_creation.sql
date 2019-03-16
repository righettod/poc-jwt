create table if not exists revoked_token(jwt_token_digest varchar(255) primary key, revokation_date timestamp default now());
