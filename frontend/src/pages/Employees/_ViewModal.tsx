import { Component } from 'solid-js';
import 'bootstrap/js/dist/modal.js';
import { Employee } from '../inc/Types';

interface Props {
    employee: Employee
}

const ViewModal: Component<Props> = (props) => {
    return (
        <div class="modal fade" id={`ViewModal${props.employee.id}`} data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticBackdropLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h1 class="modal-title fs-5" id="staticBackdropLabel">{`${props.employee?.username}`}</h1>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class='d-flex flex-wrap align-items-center justify-content-start'>
                            <div class='p-2'>
                                <p class='fs-6 fw-lighter m-0'>Employeename: </p>
                                <p class='fw-bold'>{props.employee.username}</p>
                            </div>
                            <div class='p-2'>
                                <p class='fs-6 fw-lighter m-0'>First Name: </p>
                                <p class='fw-bold'>{props.employee.first_name}</p>
                            </div>
                            <div class='p-2'>
                                <p class='fs-6 fw-lighter m-0'>Last Name: </p>
                                <p class='fw-bold'>{props.employee.last_name || 'N/A'}</p>
                            </div>
                            <div class='p-2'>
                                <p class='fs-6 fw-lighter m-0'>Email: </p>
                                <p class='fw-bold'>{props.employee.email}</p>
                            </div>
                            <div class='p-2'>
                                <p class='fs-6 fw-lighter m-0'>Phone Number: </p>
                                <p class='fw-bold'>{props.employee.phone_number}</p>
                            </div>
                            <div class='p-2'>
                                <p class='fs-6 fw-lighter m-0'>Zip Code: </p>
                                <p class='fw-bold'>{props.employee.zip_code}</p>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default ViewModal;