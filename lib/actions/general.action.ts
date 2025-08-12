"use server";

import { generateObject } from "ai";
import { google } from "@ai-sdk/google";

import { db } from "@/firebase/admin";
import { feedbackSchema } from "@/constants";

// CREATE FEEDBACK
export async function createFeedback(params: CreateFeedbackParams) {
    const { interviewId, userId, transcript, feedbackId } = params;

    try {
        // Validate transcript to avoid runtime errors
        if (!Array.isArray(transcript) || transcript.length === 0) {
            throw new Error("Transcript is empty or invalid.");
        }

        const formattedTranscript = transcript
            .map(
                (sentence: { role: string; content: string }) =>
                    `- ${sentence.role}: ${sentence.content}\n`
            )
            .join("");

        const { object } = await generateObject({
            model: google("gemini-2.0-flash-001", {
                structuredOutputs: false, // If feedbackSchema is enforced, this might need to be `true`
            }),
            schema: feedbackSchema,
            prompt: `
                You are an AI interviewer analyzing a mock interview. 
                Your task is to evaluate the candidate based on structured categories. 
                Be thorough and detailed in your analysis. Don't be lenient. 
                If there are mistakes or areas for improvement, point them out.

                Transcript:
                ${formattedTranscript}

                Please score the candidate from 0 to 100 in the following areas:
                - **Communication Skills**: Clarity, articulation, structured responses.
                - **Technical Knowledge**: Understanding of key concepts for the role.
                - **Problem-Solving**: Ability to analyze problems and propose solutions.
                - **Cultural & Role Fit**: Alignment with company values and job role.
                - **Confidence & Clarity**: Confidence in responses, engagement, and clarity.
            `,
            system:
                "You are a professional interviewer analyzing a mock interview. Your task is to evaluate the candidate based on structured categories.",
        });

        // Defensive check to avoid undefined values
        if (!object || typeof object !== "object") {
            throw new Error("AI model returned an invalid response.");
        }

        const feedback = {
            interviewId,
            userId,
            totalScore: object.totalScore ?? 0,
            categoryScores: object.categoryScores ?? {},
            strengths: object.strengths ?? [],
            areasForImprovement: object.areasForImprovement ?? [],
            finalAssessment: object.finalAssessment ?? "",
            createdAt: new Date().toISOString(),
        };

        const feedbackRef = feedbackId
            ? db.collection("feedback").doc(feedbackId)
            : db.collection("feedback").doc();

        await feedbackRef.set(feedback);

        return { success: true, feedbackId: feedbackRef.id };
    } catch (error) {
        console.error("Error saving feedback:", error);
        return { success: false, error: (error as Error).message };
    }
}

// GET INTERVIEW BY ID
export async function getInterviewById(id: string): Promise<Interview | null> {
    if (!id) return null; // Avoid empty queries
    const interviewDoc = await db.collection("interviews").doc(id).get();
    if (!interviewDoc.exists) return null;
    return { id: interviewDoc.id, ...interviewDoc.data() } as Interview;
}

// GET FEEDBACK BY INTERVIEW ID
export async function getFeedbackByInterviewId(
    params: GetFeedbackByInterviewIdParams
): Promise<Feedback | null> {
    const { interviewId, userId } = params;

    if (!interviewId || !userId) return null;

    const querySnapshot = await db
        .collection("feedback")
        .where("interviewId", "==", interviewId)
        .where("userId", "==", userId)
        .limit(1)
        .get();

    if (querySnapshot.empty) return null;

    const feedbackDoc = querySnapshot.docs[0];
    return { id: feedbackDoc.id, ...feedbackDoc.data() } as Feedback;
}

// GET LATEST INTERVIEWS
export async function getLatestInterviews(
    params: GetLatestInterviewsParams
): Promise<Interview[] | null> {
    const { userId, limit = 20 } = params;

    if (!userId) return null;

    // IMPORTANT: Firestore doesn't allow combining orderBy with '!=' without an index
    const interviews = await db
        .collection("interviews")
        .where("finalized", "==", true)
        .where("userId", "!=", userId) // Make sure index exists
        .orderBy("userId")             // Needed for inequality queries
        .orderBy("createdAt", "desc")
        .limit(limit)
        .get();

    return interviews.docs.map((doc) => ({
        id: doc.id,
        ...doc.data(),
    })) as Interview[];
}

// GET INTERVIEWS BY USER ID
export async function getInterviewsByUserId(
    userId: string
): Promise<Interview[] | null> {
    if (!userId) return null;

    const interviews = await db
        .collection("interviews")
        .where("userId", "==", userId)
        .orderBy("createdAt", "desc")
        .get();

    return interviews.docs.map((doc) => ({
        id: doc.id,
        ...doc.data(),
    })) as Interview[];
}
