create table if not exists nonce(jwt_token_digest varchar(255) primary key, gcm_nonce varchar(255) not null unique, gcm_aad varchar(255) not null unique);
create index if not exists idx_nonce on nonce(gcm_nonce);
create table if not exists revoked_token(jwt_token_digest varchar(255) primary key, revokation_date timestamp default now());
