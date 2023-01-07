import { Component, createSignal, onMount, Show } from 'solid-js';
import 'bootstrap/js/dist/modal.js';
import { Employee } from '../inc/Types';
import { createEmployee, updateEmployee } from '../../utils/EmployeesActions';
import { setStore } from '../../store';

interface Props {
    employee?: Employee,
    reFetch: Function
}

const EmployeeFormModal: Component<Props> = (props) => {
    const defaultFormFields = {
        email: "",
        first_name: "",
        last_name: "",
        password: "",
        password_confirmation: "",
        username: "",
        phone_number: "",
        zip_code: ""
    }
    const [form, setForm] = createSignal({...defaultFormFields, zip_code:0});
    const [errors, setErrors] = createSignal(defaultFormFields);

    const handleSubmit = async (e: Event) => {
        e.preventDefault();
        const res = props.employee ? await updateEmployee(form()) : await createEmployee(form());
        
        setErrors(defaultFormFields)

        if (res.status === 200) {
            document.getElementById(`closeModal${props.employee?.id}`)?.click()
            setStore({ message: res.message })
            setForm({...defaultFormFields, zip_code:0})
            props.reFetch();
        } else if (res.status === 400) {
            for (let i = 0; i < res.errors.length; i++) {
                const el = res.errors[i] ? res.errors[i] : '';
                let fieldNameArr = el.field ? el.field.split('.') : null;
                let field = fieldNameArr ? fieldNameArr[fieldNameArr.length - 1] : ''
                setErrors({ ...errors(), [field]: el.message })
            }
        }
    }

    onMount(() => {
        props.employee ? setForm({ ...form(), ...props.employee }) : '';
    })

    return (
        <div class="modal fade" id={`employeeFormModal${props.employee?.id || ''}`}
            data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1"
            aria-labelledby="staticBackdropLabel" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h1 class="modal-title fs-5" id="staticBackdropLabel">{props.employee ? `Edit ${props.employee?.username}` : 'Create Employee'}</h1>
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
                                            <span style={'color:red'}>{errors().first_name}</span>
                                        </div>
                                        <div class="col mb-3">
                                            <label for="last_name" class="form-label">Last Name</label>
                                            <input class="form-control" value={form().last_name}
                                                onChange={(e) => setForm({ ...form(), last_name: e.currentTarget.value })} />
                                            <span style={'color:red'}>{errors().last_name}</span>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col mb-3">
                                            <label for="username" class="form-label">Username</label>
                                            <input class="form-control" value={form().username}
                                                onChange={(e) => setForm({ ...form(), username: e.currentTarget.value })} />
                                            <span style={'color:red'}>{errors().username}</span>
                                        </div>
                                        <div class="col mb-3">
                                            <label for="email" class="form-label">Email address</label>
                                            <input type="email" class="form-control" aria-describedby="emailHelp"
                                                value={form().email}
                                                onChange={(e) => setForm({ ...form(), email: e.currentTarget.value })} />
                                            <span style={'color:red'}>{errors().email}</span>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col mb-3">
                                            <label for="phone_number" class="form-label">Phone Number</label>
                                            <input class="form-control" type='number' value={form().phone_number}
                                                onChange={(e) => setForm({ ...form(), phone_number: e.currentTarget.value })} />
                                            <span style={'color:red'}>{errors().phone_number}</span>
                                        </div>
                                        <div class="col mb-3">
                                            <label for="zip_code" class="form-label">Zip Code</label>
                                            <input class="form-control" type='number' min="4"
                                                value={form().zip_code}
                                                onChange={(e) => setForm({ ...form(), zip_code: parseInt(e.currentTarget.value) })} />
                                            <span style={'color:red'}>{errors().zip_code}</span>
                                        </div>
                                    </div>
                                    <Show when={!props.employee}>
                                        <div class="row">
                                            <div class="col mb-3">
                                                <label for="password" class="form-label">Password</label>
                                                <input class="form-control" type='password' value={form().password}
                                                    onChange={(e) => setForm({ ...form(), password: e.currentTarget.value })} />
                                                <span style={'color:red'}>{errors().password}</span>
                                            </div>
                                        </div>
                                    </Show>
                                </div>
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" id={`closeModal${props.employee?.id}`} data-bs-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-primary" onClick={handleSubmit}>Submit</button>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default EmployeeFormModal;