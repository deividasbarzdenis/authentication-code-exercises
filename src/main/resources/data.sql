insert into users (username, password, enabled) values ('admin', 'demo', true);
insert into users (username, password, enabled) values ('user1', 'demo', true);
insert into users (username, password, enabled) values ('user2', 'demo', true);

insert into authorities (username, authority) values ('admin', 'ROLE_ADMIN');
insert into authorities (username, authority) values ('user1', 'ROLE_USER');
insert into authorities (username, authority) values ('user2', 'ROLE_USER');
