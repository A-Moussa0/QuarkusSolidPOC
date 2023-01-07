import { useNavigate } from '@solidjs/router';
import { Component, onMount } from 'solid-js';
import { login } from '../../utils/Auth';

interface Props {
    isLogin?: boolean
}

const FacebookButton: Component<Props> = (props) => {
    const navigate = useNavigate();

    const handleCredentialResponse = (res: any) => {
        res.status === 'connected' ? login(res.authResponse.accessToken) : ''
        navigate("/");
    }

    onMount(() => {
        FB.getLoginStatus(function (response) {
            handleCredentialResponse(response);
        });

        window.fbAsyncInit = function () {
            FB.init({
                appId: import.meta.env.VITE_FACEBOOK_APP_ID,
                cookie: true,
                xfbml: true,
                version: '{api-version}'
            });

            FB.AppEvents.logPageView();

        };

        (function (d, s, id) {
            var js, fjs = d.getElementsByTagName(s)[0];
            if (d.getElementById(id)) { return; }
            js = d.createElement(s); js.id = id;
            js.src = "https://connect.facebook.net/en_US/sdk.js";
            fjs.parentNode.insertBefore(js, fjs);
        }(document, 'script', 'facebook-jssdk'));
    })

    return (
        <>
            <div id="fb-root"></div>

            <div class="fb-login-button" data-width="187" data-size="large" data-button-type="continue_with" 
            data-layout="default" data-auto-logout-link="false" data-use-continue-as="true"></div>
        </>
    )
}

export default FacebookButton;