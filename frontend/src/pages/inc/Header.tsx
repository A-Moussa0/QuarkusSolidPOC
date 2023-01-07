import 'bootstrap/js/dist/collapse.js';
import { Component, Match, Show, Switch } from 'solid-js';
import { A } from '@solidjs/router';
import logo from '../../logo.svg';
import { store } from '../../store';


const Header: Component = () => {
    return (
        <nav class="navbar navbar-expand-lg fixed-top bg-light">
            <div class="container">
                <A class='navbar-brand' href="/" rel="noopener noreferrer" end>
                    <img alt="logo" src={logo} width="30" height="30" /></A>

                <button class="navbar-toggler" type="button" data-bs-toggle="collapse"
                    data-bs-target="#navbarColor01" aria-controls="navbarColor01" aria-expanded="false"
                    aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarColor01">
                    <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                        <li class="nav-item">
                            <A class='nav-link' href="/" rel="noopener noreferrer" end>Home</A>
                            {/* <a class="nav-link active" aria-current="page" href="#">Home</a> */}
                        </li>
                        <Show when={store.token}>
                            <li class="nav-item">
                                <A class='nav-link' href="/employees" rel="noopener noreferrer" end>Employees</A>
                            </li>
                        </Show>
                    </ul>

                    <div class="d-flex" role="search">
                        <Switch fallback={<A class='btn btn-outline-danger me-2' href="/logout" rel="noopener noreferrer">Logout</A>}>
                            <Match when={!store.token}>
                                <A class='btn btn-outline-primary me-2'
                                    href={`${import.meta.env.VITE_AUTH_SERVER_URL + window.location.origin + import.meta.env.VITE_AUTH_REDIRECT_URL}`}
                                    rel="noopener noreferrer">Login / Register</A>
                                {/* <A class='btn btn-outline-success' href="/signup" rel="noopener noreferrer">Sign-up</A> */}
                            </Match>
                        </Switch>
                    </div>
                </div>
            </div>
        </nav>
    )
}

export default Header;