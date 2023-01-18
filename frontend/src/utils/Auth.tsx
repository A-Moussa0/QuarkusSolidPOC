import { useNavigate } from "@solidjs/router";
import { setStore, store } from "../store";
import { backendLogout } from "./LoginAction";

const authenticated = (authenticated: boolean) => {
    const navigate = useNavigate();
    if (authenticated && !store.token) {
        setStore({ error: "Not Authorized" })
        navigate("/")
        return false;
    } else if (!authenticated && store.token) {
        navigate("/")
        return false;
    }
    return true;
}

const logout = () => {
    store.token ? backendLogout() : '';
    setStore({ token: "", username: "", message: "You are logged out" })
    sessionStorage.removeItem("token");
    sessionStorage.removeItem("username");
    setTimeout(() => location.assign(`/`), 400);
}

const login = (token: string) => {
    sessionStorage.setItem("token", token);
    const tokenDecoded = parseJwt(token);

    setStore({ token, username: tokenDecoded.name })
}

const parseJwt = (token: string) => {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
}

export { authenticated, logout, login }