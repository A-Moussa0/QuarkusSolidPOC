import { Show, createEffect } from "solid-js";
import { setStore, store } from "../../store";
import { Component } from 'solid-js';
import 'bootstrap/js/dist/alert.js';

const Alert: Component = () => {
    const close = () => {
        setStore({ message: "", error: "" })
    }

    createEffect(() => {
        if(store.message)
            setTimeout(() => document.getElementById(`msg-close-btn`)?.click(), 5000)
        
        if(store.error)
            setTimeout(() => document.getElementById(`error-close-btn`)?.click(), 5000)
    });

    return (
        <div class="d-flex justify-content-center">
            <div class="container d-flex justify-content-center position-absolute">
                <Show when={store.error}>
                    <div class="alert alert-danger alert-dismissible fade show px-5 mt-2" id="error-alert" role="alert">
                        <span class="mx-3">{store.error}</span> <br />
                        <button type="button" id="error-close-btn" class="btn-close" onClick={close} data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                </Show>
                <Show when={store.message}>
                    <div class="alert alert-success alert-dismissible fade show px-5 mt-2" id="message-alert" role="alert">
                        <span class="mx-3">{store.message}</span> <br />
                        <button type="button" id="msg-close-btn" class="btn-close" onClick={close} data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                </Show>
            </div>
        </div>
    )
}

export default Alert;
