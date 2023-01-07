import { useNavigate } from '@solidjs/router';
import { Component, onMount } from 'solid-js';
import { login } from '../../utils/Auth';

interface Props {
    isLogin?: boolean
}

const GoogleButton: Component<Props> = (props) => {
    const navigate = useNavigate();

    const handleCredentialResponse = (response: any) => {
        login(response.credential)
        navigate("/");
    }

    onMount(() => {
        google.accounts.id.initialize({
            client_id: import.meta.env.VITE_GOOGLE_CLIENT_ID,
            callback: handleCredentialResponse
        });
        google.accounts.id.renderButton(
            document.getElementById("googleBtn"),
            { text: props.isLogin ? "signin_with" : "signup_with", theme: "filled_black", type:'standard', size: "large", shape: 'rectangular' }  // customization attributes
        );
        google.accounts.id.prompt(); // also display the One Tap dialog
    })

    return (
        <div id="googleBtn"></div>
    )
}

export default GoogleButton;