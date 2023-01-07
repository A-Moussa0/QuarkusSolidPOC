import { SignupFormFields } from "../pages/inc/Types";
import { login } from "./Auth";

const submit = async (form: SignupFormFields) => {
    let res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/signup`, {
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

export { submit };