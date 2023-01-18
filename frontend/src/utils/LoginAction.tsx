import { LoginFormFields } from "../pages/inc/Types";
import { store } from "../store";
import { login } from "./Auth";

const submit = async (form: LoginFormFields) => {
    let res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/login`, {
        method: 'POST',
        cache: 'no-cache',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(form)
    })

    if (res.status === 200) {
        let data = await res.json();
        login(data.token);

        return {sent: true};
    }

    return {sent:false, errors: []};
}

const exchangeToken = async (auth_code: string) => {
    let res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/auth/exchange-token`, {
        method: 'POST',
        cache: 'no-cache',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({auth_code, redirect_uri: window.location.origin+import.meta.env.VITE_AUTH_REDIRECT_URL})
    })

    if (res.status === 200) {
        let data = await res.json();
        login(data.access_token);

        return {sent: true};
    }else if(res.status === 400){
        return {sent:false, errors: ["Couldn't authenticate please try again"]};
    }

    return {sent:false, errors: []};
}

const backendLogout = async () => {
    let res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/auth/logout`, {
        method: 'POST',
        cache: 'no-cache',
        credentials: 'include',
        headers: {
            'Authorization': `Bearer ${store.token}`
        }
    })

    if (res.status === 200) {
        return {sent: true};
    }else if(res.status === 400){
        return {sent:false, errors: ["Couldn't authenticate please try again"]};
    }

    return {sent:false, errors: []};
}

const refreshAccessToken = async () => {
    let res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/auth/refresh-access`, {
        method: 'POST',
        cache: 'no-cache',
        credentials: 'include',
        headers: {
            'Authorization': `Bearer ${store.token}`
        },
    })

    if (res.status === 200) {
        let data = await res.json();
        login(data.access_token);

        return {sent: true};
    }else if(res.status === 400){
        return {sent:false, errors: ["Couldn't authenticate please try again"]};
    }

    return {sent:false, errors: []};
}

export { submit, exchangeToken, refreshAccessToken, backendLogout};