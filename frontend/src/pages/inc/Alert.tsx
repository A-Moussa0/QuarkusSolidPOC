import { Show } from "solid-js";
import { setStore, store } from "../../store";
import { Component } from 'solid-js';
import 'bootstrap/js/dist/alert.js';

const Alert: Component = () => {
    const close = () => {
        setStore({message: ""})
    }
    return (
        <div class=" d-flex justify-content-center">
            <Show when={store.error}>
                <div class="container d-flex justify-content-center position-absolute">
                    <div class="alert alert-danger alert-dismissible fade show px-5 mt-2" id="error-alert" role="alert">
                        <span class="mx-3">{store.error}</span> <br />
                        <button type="button" class="btn-close" onClick={close} data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                </div>
            </Show>
            <Show when={store.message}>
                <div class="container d-flex justify-content-center position-absolute">
                    <div class="alert alert-success alert-dismissible fade show px-5 mt-2" id="message-alert" role="alert">
                        <span class="mx-3">{store.message}</span> <br />
                        <button type="button" class="btn-close" onClick={close} data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                </div>
            </Show>
        </div>
    )
}

export default Alert;
