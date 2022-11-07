import { Component, createSignal, onMount, Show } from 'solid-js';
import 'bootstrap/js/dist/modal.js';
import { Response, User } from './Types';
import { createUser, updateUser } from '../../components/UsersActions';
import { setStore } from '../../store';

interface Props {
    user?: User,
    reFetch: Function
}

const UserFormModal: Component<Props> = (props) => {
    const [form, setForm] = createSignal({
        email: "",
        first_name: "",
        last_name: "",
        password: "",
        password_confirmation: "",
        username: "",
        phone_number: "",
        zip_code: 0,
    });

    const handleSubmit = async (e: Event) => {
        e.preventDefault();
        const res = props.user ? await updateUser(form()) : await createUser(form());

        if (res.status === 200) {
            document.getElementById(`closeModal${props.user?.id}`)?.click()
            setStore({ message: res.message })
            props.reFetch();
        }
    }

    onMount(() => {
        props.user ? setForm({ ...form(), ...props.user }) : '';
    })

    return (
        <div class="modal fade" id={`userFormModal${props.user?.id || ''}`}
            data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1"
            aria-labelledby="staticBackdropLabel" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h1 class="modal-title fs-5" id="staticBackdropLabel">{props.user ? `Edit ${props.user?.username}` : 'Create User'}</h1>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <form onSubmit={handleSubmit} class='bg-white p-5 rounded'>
                            <div class="row">
                                <div class='col'>
                                    <div class="row">
                                        <div class="col mb-3">
                                            <label for="first_name" class="form-label">First Name</label>
                                            <input class="form-control" value={form().first_name}
                                                onChange={(e) => setForm({ ...form(), first_name: e.currentTarget.value })} />
                                        </div>
                                        <div class="col mb-3">
                                            <label for="last_name" class="form-label">Last Name</label>
                                            <input class="form-control" value={form().last_name}
                                                onChange={(e) => setForm({ ...form(), last_name: e.currentTarget.value })} />
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col mb-3">
                                            <label for="username" class="form-label">Username</label>
                                            <input class="form-control" value={form().username}
                                                onChange={(e) => setForm({ ...form(), username: e.currentTarget.value })} />
                                        </div>
                                        <div class="col mb-3">
                                            <label for="email" class="form-label">Email address</label>
                                            <input type="email" class="form-control" aria-describedby="emailHelp"
                                                value={form().email}
                                                onChange={(e) => setForm({ ...form(), email: e.currentTarget.value })} />
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col mb-3">
                                            <label for="phone_number" class="form-label">Phone Number</label>
                                            <input class="form-control" type='number' value={form().phone_number}
                                                onChange={(e) => setForm({ ...form(), phone_number: e.currentTarget.value })} />
                                        </div>
                                        <div class="col mb-3">
                                            <label for="zip_code" class="form-label">Zip Code</label>
                                            <input class="form-control" type='number' min="4"
                                                value={form().zip_code}
                                                onChange={(e) => setForm({ ...form(), zip_code: parseInt(e.currentTarget.value) })} />
                                        </div>
                                    </div>
                                    <Show when={!props.user}>
                                        <div class="row">
                                            <div class="col mb-3">
                                                <label for="password" class="form-label">Password</label>
                                                <input class="form-control" type='password' value={form().password}
                                                    onChange={(e) => setForm({ ...form(), password: e.currentTarget.value })} />
                                            </div>
                                            <div class="col mb-3">
                                                <label for="password_confirmation" class="form-label">Password Confirmation</label>
                                                <input class="form-control" type='password'
                                                    value={form().password_confirmation}
                                                    onChange={(e) => setForm({ ...form(), password_confirmation: e.currentTarget.value })} />
                                            </div>
                                        </div>
                                    </Show>
                                </div>
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" id={`closeModal${props.user?.id}`} data-bs-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-primary" onClick={handleSubmit}>Submit</button>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default UserFormModal;