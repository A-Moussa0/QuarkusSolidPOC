CREATE DATABASE quarkus_solid_poc;
CREATE USER quarkus WITH PASSWORD 'password';
GRANT ALL privileges ON DATABASE quarkus_solid_poc TO quarkus;
\c quarkus_solid_poc;
GRANT ALL ON schema public TO quarkus;