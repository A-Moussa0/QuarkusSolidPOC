import { createStore } from "solid-js/store";

const [store, setStore] = createStore({
    token: sessionStorage.getItem("token") || "",
    // rftkn: sessionStorage.getItem("rftkn") || "",
    username: sessionStorage.getItem("username") || "",
    error:"",
    message: ""
  });

export {store, setStore}