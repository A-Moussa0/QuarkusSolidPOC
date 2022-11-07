import { Component } from 'solid-js';
import logo from '../logo.svg';
import styles from './Home.module.css';

const Home: Component = () => {
    return (
        <div class={styles.App}>
        <div class={styles.header}>
          <img src={logo} class={styles.logo} alt="logo" />
          <p>
            Welcome to Java-Solid POC Project.
          </p>
        </div>
      </div>
    )
}

export default Home;