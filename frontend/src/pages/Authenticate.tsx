import { useNavigate } from '@solidjs/router';
import { setStore } from "../store";
import { Component, onMount } from 'solid-js';
import { authenticated } from '../utils/Auth';
import { exchangeToken } from '../utils/LoginAction';

const Authenticate: Component = () => {
    authenticated(false)

    const navigate = useNavigate();

    onMount(async () => {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code') || '';
        if (!code)
            setStore({ error: "Not Authorized" })

        const res = await exchangeToken(code)
        if (!res.sent)
            setStore({ error: res.errors && res.errors[0] || 'Please try again' })

        navigate('/');

    })

    return (
        <div class="container">
            <div class='row align-items-center vh-100'>
                <div class='col'>
                    <h1>Hold On...</h1>
                </div>
            </div>
        </div>
    )
}

export default Authenticate;