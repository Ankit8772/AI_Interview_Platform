'use server';

import { db, auth } from "@/firebase/admin";
import { cookies } from "next/headers";
import { firestore } from "firebase-admin";

const ONE_WEEK = 60 * 60 * 24 * 7; // in seconds

// ==== Type definitions ====
interface SignUpParams {
    uid: string;
    name: string;
    email: string;
    password: string;
}

interface SignInParams {
    email: string;
    idToken: string;
}

interface User {
    id: string;
    uid: string;
    name: string;
    email: string;
    createdAt: string;
}

interface Interview {
    id: string;
    [key: string]: any;
}

interface GetLatestInterviewsParams {
    userId?: string;
    limit?: number;
}

// ==== SIGN UP ====
export async function signUp(params: SignUpParams) {
    const { uid, name, email } = params;

    try {
        const userRecord = await db.collection('users').doc(uid).get();

        if (userRecord.exists) {
            return { success: false, message: "User already exists. Please sign in instead" };
        }

        await db.collection('users').doc(uid).set({
            name,
            email,
            createdAt: new Date().toISOString(),
        });

        return { success: true, message: "Account created successfully. Please sign in." };
    } catch (e: any) {
        console.error("Error creating user", e);

        if (e.code === 'auth/email-already-in-use') {
            return { success: false, message: "Email already in use" };
        }

        if (e.code === 'permission-denied') {
            return { success: false, message: "Permission denied. Please check your Firestore rules." };
        }

        return { success: false, message: "Failed to register user" };
    }
}

// ==== SIGN IN ====
export async function signIn(params: SignInParams) {
    const { email, idToken } = params;

    try {
        const decodedToken = await auth.verifyIdToken(idToken);

        if (!decodedToken || decodedToken.email !== email) {
            return { success: false, message: "Invalid authentication token" };
        }

        const userDoc = await db.collection('users').doc(decodedToken.uid).get();

        if (!userDoc.exists) {
            return { success: false, message: "User does not exist. Create an account instead." };
        }

        await setSessionCookie(idToken);

        return { success: true, message: "Signed in successfully" };
    } catch (e: any) {
        console.error("Sign in error:", e);

        if (e.code === 'auth/id-token-expired') {
            return { success: false, message: "Session expired. Please sign in again." };
        }
        if (e.code === 'auth/id-token-revoked') {
            return { success: false, message: "Access revoked. Please sign in again." };
        }
        if (e.code === 'auth/invalid-id-token') {
            return { success: false, message: "Invalid authentication. Please try again." };
        }

        return { success: false, message: "Failed to log into account." };
    }
}

// ==== SET SESSION COOKIE ====
export async function setSessionCookie(idToken: string) {
    try {
        const cookieStore = await cookies();

        const sessionCookie = await auth.createSessionCookie(idToken, {
            expiresIn: ONE_WEEK * 1000, // milliseconds
        });

        cookieStore.set('session', sessionCookie, {
            maxAge: ONE_WEEK,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            path: '/',
            sameSite: 'lax',
        });

        return { success: true, message: "Session cookie set successfully" };
    } catch (e) {
        console.error("Error setting session cookie:", e);
        throw new Error("Failed to create session");
    }
}

// ==== SIGN OUT ====
export async function signOut() {
    try {
        const cookieStore = await cookies();
        cookieStore.delete('session');
        return { success: true, message: "Signed out successfully" };
    } catch (e) {
        console.error("Error signing out:", e);
        return { success: false, message: "Failed to sign out" };
    }
}

// ==== GET CURRENT USER ====
export async function getCurrentUser(): Promise<User | null> {
    const cookieStore = await cookies();
    const sessionCookie = cookieStore.get('session')?.value;

    if (!sessionCookie) return null;

    try {
        const decodedClaims = await auth.verifySessionCookie(sessionCookie, true);
        const userRecord = await db.collection('users').doc(decodedClaims.uid).get();

        if (!userRecord.exists) return null;

        return {
            id: userRecord.id,
            uid: decodedClaims.uid,
            email: decodedClaims.email!,
            ...userRecord.data(),
        } as User;
    } catch (e) {
        console.error("Error getting current user:", e);
        return null;
    }
}

// ==== IS AUTHENTICATED ====
export async function isAuthenticated(): Promise<boolean> {
    const user = await getCurrentUser();
    return !!user;
}

// ==== GET INTERVIEWS BY USER ====
export async function getInterviewByUserId(userId: string): Promise<Interview[] | null> {
    if (!userId) {
        throw new Error("userId is required for getInterviewByUserId");
    }

    const interviewsSnap = await db
        .collection('interviews')
        .where('userId', '==', userId)
        .orderBy('createdAt', 'desc')
        .get();

    return interviewsSnap.docs.map(doc => ({ id: doc.id, ...doc.data() })) as Interview[];
}

// ==== GET LATEST INTERVIEWS ====
export async function getLatestInterviews(params: GetLatestInterviewsParams): Promise<Interview[] | null> {
    const { userId, limit = 20 } = params;

    let queryRef: FirebaseFirestore.Query = db
        .collection('interviews')
        .where('finalized', '==', true)
        .orderBy('createdAt', 'desc')
        .limit(limit);

    // Only filter out the current user's interviews if userId is defined
    if (userId) {
        queryRef = queryRef.where('userId', '!=', userId);
    }

    const interviewsSnap = await queryRef.get();

    return interviewsSnap.docs.map(doc => ({ id: doc.id, ...doc.data() })) as Interview[];
}
