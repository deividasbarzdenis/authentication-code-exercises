
insert into users (username, password, enabled) values ('admin', '$argon2id$v=19$m=4096,t=3,p=1$dz8TS6BBtBt1Z5u3xvO0ow$I++MWv9jyWzaVIuabSD/yfhIely/wStG2DtapC4K3YY', true);
insert into users (username, password, enabled) values ('user1', '$argon2id$v=19$m=4096,t=3,p=1$dz8TS6BBtBt1Z5u3xvO0ow$I++MWv9jyWzaVIuabSD/yfhIely/wStG2DtapC4K3YY', true);
insert into users (username, password, enabled) values ('user2', '$argon2id$v=19$m=4096,t=3,p=1$dz8TS6BBtBt1Z5u3xvO0ow$I++MWv9jyWzaVIuabSD/yfhIely/wStG2DtapC4K3YY', true);

insert into authorities (username, authority) values ('admin', 'ROLE_ADMIN');
insert into authorities (username, authority) values ('user1', 'ROLE_USER');
insert into authorities (username, authority) values ('user2', 'ROLE_USER');
