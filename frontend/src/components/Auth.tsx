import { useNavigate } from "@solidjs/router";
import { setStore, store } from "../store";

const parseJwt = (token: string) => {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
}


const authenticated = (authenticated: boolean) => {
    const navigate = useNavigate();
    if (authenticated && !store.token) {
        setStore({ error: "Not Authorized" })
        navigate("/login")
    }else if (!authenticated && store.token){
        navigate("/")
    }
}

const logout = () => {
    setStore({ token: "", username: "", message: "You are logged out" })
    sessionStorage.removeItem("token");
    sessionStorage.removeItem("username");

    const navigate = useNavigate();
    navigate('/')
}

const login = (token: string) => {
    sessionStorage.setItem("token", token);
    const tokenDecoded = parseJwt(token);
    
    setStore({ token, username: tokenDecoded.name, message: `Welcome ${tokenDecoded.name}` })
}

export { authenticated, logout, login }