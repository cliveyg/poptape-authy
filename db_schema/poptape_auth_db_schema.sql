--
-- PostgreSQL database dump
--

-- Dumped from database version 11.3
-- Dumped by pg_dump version 11.3

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: poptape_auth_test
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


ALTER TABLE public.alembic_version OWNER TO poptape_auth_test;

--
-- Name: role; Type: TABLE; Schema: public; Owner: poptape_auth_test
--

CREATE TABLE public.role (
    id integer NOT NULL,
    name character varying(50),
    description character varying(100),
    level integer
);


ALTER TABLE public.role OWNER TO poptape_auth_test;

--
-- Name: role_id_seq; Type: SEQUENCE; Schema: public; Owner: poptape_auth_test
--

CREATE SEQUENCE public.role_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.role_id_seq OWNER TO poptape_auth_test;

--
-- Name: role_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: poptape_auth_test
--

ALTER SEQUENCE public.role_id_seq OWNED BY public.role.id;


--
-- Name: user_role; Type: TABLE; Schema: public; Owner: poptape_auth_test
--

CREATE TABLE public.user_role (
    user_id integer NOT NULL,
    role_id integer NOT NULL
);


ALTER TABLE public.user_role OWNER TO poptape_auth_test;

--
-- Name: users; Type: TABLE; Schema: public; Owner: poptape_auth_test
--

CREATE TABLE public.users (
    id integer NOT NULL,
    public_id character varying(50),
    username character varying(50),
    password character varying(200) NOT NULL,
    email character varying(100),
    created timestamp without time zone NOT NULL,
    last_login timestamp without time zone,
    deleted boolean,
    delete_date timestamp without time zone,
    password_reset_datetime timestamp without time zone,
    password_reset_string character varying(160),
    validated boolean,
    validation_string character varying(160)
);


ALTER TABLE public.users OWNER TO poptape_auth_test;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: poptape_auth_test
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.users_id_seq OWNER TO poptape_auth_test;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: poptape_auth_test
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: role id; Type: DEFAULT; Schema: public; Owner: poptape_auth_test
--

ALTER TABLE ONLY public.role ALTER COLUMN id SET DEFAULT nextval('public.role_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: poptape_auth_test
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: poptape_auth_test
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: role role_level_key; Type: CONSTRAINT; Schema: public; Owner: poptape_auth_test
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_level_key UNIQUE (level);


--
-- Name: role role_name_key; Type: CONSTRAINT; Schema: public; Owner: poptape_auth_test
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_name_key UNIQUE (name);


--
-- Name: role role_pkey; Type: CONSTRAINT; Schema: public; Owner: poptape_auth_test
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_pkey PRIMARY KEY (id);


--
-- Name: user_role user_role_pkey; Type: CONSTRAINT; Schema: public; Owner: poptape_auth_test
--

ALTER TABLE ONLY public.user_role
    ADD CONSTRAINT user_role_pkey PRIMARY KEY (user_id, role_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: poptape_auth_test
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: poptape_auth_test
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_public_id_key; Type: CONSTRAINT; Schema: public; Owner: poptape_auth_test
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_public_id_key UNIQUE (public_id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: poptape_auth_test
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: user_role user_role_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: poptape_auth_test
--

ALTER TABLE ONLY public.user_role
    ADD CONSTRAINT user_role_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.role(id);


--
-- Name: user_role user_role_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: poptape_auth_test
--

ALTER TABLE ONLY public.user_role
    ADD CONSTRAINT user_role_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- PostgreSQL database dump complete
--

