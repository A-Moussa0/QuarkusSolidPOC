import { Component } from 'solid-js';
import 'bootstrap/js/dist/modal.js';
import { User } from './Types';

interface Props {
    user: User
}

const UserViewModal: Component<Props> = (props) => {
    return (
        <div class="modal fade" id={`userViewModal${props.user.id}`} data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticBackdropLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h1 class="modal-title fs-5" id="staticBackdropLabel">{`${props.user?.username}`}</h1>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class='d-flex flex-wrap align-items-center justify-content-center'>
                            <div class='p-2'>
                                <p class='fs-6 fw-lighter m-0'>Username: </p>
                                <p class='fw-bold'>{props.user.username}</p>
                            </div>
                            <div class='p-2'>
                                <p class='fs-6 fw-lighter m-0'>First Name: </p>
                                <p class='fw-bold'>{props.user.first_name}</p>
                            </div>
                            <div class='p-2'>
                                <p class='fs-6 fw-lighter m-0'>Last Name: </p>
                                <p class='fw-bold'>{props.user.last_name || 'N/A'}</p>
                            </div>
                            <div class='p-2'>
                                <p class='fs-6 fw-lighter m-0'>Email: </p>
                                <p class='fw-bold'>{props.user.email}</p>
                            </div>
                            <div class='p-2'>
                                <p class='fs-6 fw-lighter m-0'>Phone Number: </p>
                                <p class='fw-bold'>{props.user.phone_number}</p>
                            </div>
                            <div class='p-2'>
                                <p class='fs-6 fw-lighter m-0'>Zip Code: </p>
                                <p class='fw-bold'>{props.user.zip_code}</p>
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

export default UserViewModal;