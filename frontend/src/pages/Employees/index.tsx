import { Component, createSignal, For, onMount, Show } from 'solid-js';
import { authenticated } from '../../utils/Auth';
import { deleteEmployee, getEmployees, setAlert } from '../../utils/EmployeesActions';
import { Employee } from '../inc/Types';
import FormModal from './_FormModal';
import ViewModal from './_ViewModal';

const EmployeeIndex: Component = () => {
    const [employees, setEmployees] = createSignal([]);

    const fetchEmployees = async () => {
        const res = await getEmployees();
        if (res.status === 200) {
            setEmployees(res.data.sort((a: Employee, b: Employee) => a.id && b.id ? b.id - a.id : false))
        } else if (res.status === 401) {
            setAlert('Not Authenticated!, Please logout and login again', true)
        }
    }

    onMount(() => {
        authenticated(true) ? fetchEmployees() : ''
    })

    const onDelete = async (id: number) => {
        const res = await deleteEmployee(id)
        if (res.status === 200) {
            fetchEmployees()
        }
    }

    return (
        <div class='container'>
            <div class='row bg-light p-5 mt-5 align-items-center rounded'>
                <div class='d-flex flex-row justify-content-between mb-4'>
                    <h2>Employees</h2>
                    <button class='btn btn-success' data-bs-toggle="modal" data-bs-target='#employeeFormModal'>Create Employee</button>
                    <FormModal reFetch={fetchEmployees} />
                </div>
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th scope="col">#</th>
                                <th scope="col">Username</th>
                                <th scope="col">Email</th>
                                <th scope="col">Phone Number</th>
                                <th scope="col">Zip Code</th>
                                <th scope="col">Status</th>
                                <th scope="col">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For each={employees()}>{(employee: Employee) =>
                                <tr>
                                    <th scope="row">{employee.id}</th>
                                    <td>{employee.username}</td>
                                    <td>{employee.email}</td>
                                    <td>{employee.phone_number}</td>
                                    <td>{employee.zip_code}</td>
                                    <td style={'color:' + (employee.status === 'DEL' ? 'red' : 'green')}>{employee.status}</td>
                                    <td class='d-flex flex-row justify-content-center'>
                                        <Show when={employee.status !== 'DEL'}>
                                            <span role="button" class='link-primary mx-1' data-bs-toggle="modal" data-bs-target={`#employeeFormModal${employee.id}`}><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-input-cursor-text" viewBox="0 0 16 16">
                                                <path fill-rule="evenodd" d="M5 2a.5.5 0 0 1 .5-.5c.862 0 1.573.287 2.06.566.174.099.321.198.44.286.119-.088.266-.187.44-.286A4.165 4.165 0 0 1 10.5 1.5a.5.5 0 0 1 0 1c-.638 0-1.177.213-1.564.434a3.49 3.49 0 0 0-.436.294V7.5H9a.5.5 0 0 1 0 1h-.5v4.272c.1.08.248.187.436.294.387.221.926.434 1.564.434a.5.5 0 0 1 0 1 4.165 4.165 0 0 1-2.06-.566A4.561 4.561 0 0 1 8 13.65a4.561 4.561 0 0 1-.44.285 4.165 4.165 0 0 1-2.06.566.5.5 0 0 1 0-1c.638 0 1.177-.213 1.564-.434.188-.107.335-.214.436-.294V8.5H7a.5.5 0 0 1 0-1h.5V3.228a3.49 3.49 0 0 0-.436-.294A3.166 3.166 0 0 0 5.5 2.5.5.5 0 0 1 5 2z" />
                                                <path d="M10 5h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1h-4v1h4a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2h-4v1zM6 5V4H2a2 2 0 0 0-2 2v4a2 2 0 0 0 2 2h4v-1H2a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h4z" />
                                            </svg></span>
                                        </Show>
                                        <span role="button" class='link-primary mx-1' data-bs-toggle="modal" data-bs-target={`#ViewModal${employee.id}`}>
                                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-eye" viewBox="0 0 16 16">
                                                <path d="M16 8s-3-5.5-8-5.5S0 8 0 8s3 5.5 8 5.5S16 8 16 8zM1.173 8a13.133 13.133 0 0 1 1.66-2.043C4.12 4.668 5.88 3.5 8 3.5c2.12 0 3.879 1.168 5.168 2.457A13.133 13.133 0 0 1 14.828 8c-.058.087-.122.183-.195.288-.335.48-.83 1.12-1.465 1.755C11.879 11.332 10.119 12.5 8 12.5c-2.12 0-3.879-1.168-5.168-2.457A13.134 13.134 0 0 1 1.172 8z" />
                                                <path d="M8 5.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zM4.5 8a3.5 3.5 0 1 1 7 0 3.5 3.5 0 0 1-7 0z" />
                                            </svg>
                                        </span>
                                        <Show when={employee.status !== 'DEL'}>
                                            <span onClick={() => confirm('Delete this user?') ? onDelete(employee.id ?? 0) : ''} role="button" class='link-danger mx-1'><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-x" viewBox="0 0 16 16">
                                                <path fill-rule="evenodd" d="M6.146 5.146a.5.5 0 0 1 .708 0L8 6.293l1.146-1.147a.5.5 0 1 1 .708.708L8.707 7l1.147 1.146a.5.5 0 0 1-.708.708L8 7.707 6.854 8.854a.5.5 0 1 1-.708-.708L7.293 7 6.146 5.854a.5.5 0 0 1 0-.708z" />
                                                <path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5V2zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1H4z" />
                                            </svg></span>
                                        </Show>
                                        <ViewModal employee={employee} />
                                        <FormModal employee={employee} reFetch={fetchEmployees} />
                                    </td>
                                </tr>
                            }</For>
                        </tbody>
                    </table>
                    <Show when={employees().length <= 0}>
                        <h4>No Records Available...</h4>
                    </Show>
                </div>
            </div>
        </div>
    )
}

export default EmployeeIndex;