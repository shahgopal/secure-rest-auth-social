create sequence hibernate_sequence start with 1 increment by 1
create table app_user (id bigint not null, account_non_expired boolean, account_non_locked boolean, credentials_non_expired boolean, email varchar(255), enabled boolean, first_name varchar(255), last_name varchar(255), last_password_reset timestamp, password varchar(255), sign_in_provider integer, username varchar(255), primary key (id))
create table user_roles (user_id bigint not null, roles varchar(255))
alter table app_user add constraint UK_3k4cplvh82srueuttfkwnylq0 unique (username)
alter table user_roles add constraint FK6fql8djp64yp4q9b3qeyhr82b foreign key (user_id) references app_user
