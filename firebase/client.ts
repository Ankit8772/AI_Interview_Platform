// Import the functions you need from the SDKs you need
import { initializeApp,getApp,getApps } from "firebase/app";
import { getAuth } from "firebase/auth";
import {getFirestore} from "firebase/firestore";

const firebaseConfig = {
    apiKey: "AIzaSyDyC0h0k-DIs9rTz_z3Qnn0MUpjh7tPB8M",
    authDomain: "intrevue.firebaseapp.com",
    projectId: "intrevue",
    storageBucket: "intrevue.firebasestorage.app",
    messagingSenderId: "387590549885",
    appId: "1:387590549885:web:0f0f4714cd792ea1e9dc14",
    measurementId: "G-5GNG7T536H"
};

// Initialize Firebase
const app = !getApps.length? initializeApp(firebaseConfig):getApp();

export const auth = getAuth(app);
export const db = getFirestore(app);