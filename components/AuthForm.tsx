"use client"

import { zodResolver } from "@hookform/resolvers/zod"
import { useForm } from "react-hook-form"
import { z } from "zod"
import { Button } from "@/components/ui/button"
import { Form } from "@/components/ui/form"
import Image from "next/image"
import Link from "next/link"
import { toast } from "sonner"
import FormField from "@/components/FormField"
import { useRouter } from "next/navigation"
import { createUserWithEmailAndPassword, signInWithEmailAndPassword } from "firebase/auth"
import { auth } from "@/firebase/client" // Your Firebase client config
import { signIn, signUp } from "@/lib/actions/auth.action"

type FormType = "sign-in" | "sign-up"

const authFormSchema = (type: FormType) => {
    return z.object({
        name: type === "sign-up" ? z.string().min(3) : z.string().optional(),
        email: z.string().email(),
        password: z.string().min(3),
    })
}

const AuthForm = ({ type }: { type: FormType }) => {
    const router = useRouter()
    const formSchema = authFormSchema(type)

    const form = useForm<z.infer<typeof formSchema>>({
        resolver: zodResolver(formSchema),
        defaultValues: {
            name: "",
            email: "",
            password: "",
        },
    })

    async function onSubmit(values: z.infer<typeof formSchema>) {
        try {
            if (type === "sign-up") {
                const { name, email, password } = values

                const userCredentials = await createUserWithEmailAndPassword(auth, email, password)

                const result = await signUp({
                    uid: userCredentials.user.uid,
                    name: name!,
                    email,
                    password,
                })

                if (!result?.success) {
                    toast.error(result?.message)
                    return
                }

                toast.success("Account created successfully! Please sign in")
                router.push("/sign-in")
            } else {
                const { email, password } = values

                const userCredential = await signInWithEmailAndPassword(auth, email, password)

                // Get the ID token from the user credential
                const idToken = await userCredential.user.getIdToken()

                if (!idToken) {
                    toast.error('Sign in failed')
                    return
                }

                await signIn({
                    email,
                    idToken
                })

                toast.success("Signed in successfully")
                router.push("/")
            }
        } catch (error: any) {
            console.error(error)

            // Handle specific Firebase auth errors
            let errorMessage = "An unexpected error occurred"

            if (error?.code) {
                switch (error.code) {
                    case 'auth/user-not-found':
                        errorMessage = "No account found with this email"
                        break
                    case 'auth/wrong-password':
                        errorMessage = "Incorrect password"
                        break
                    case 'auth/invalid-email':
                        errorMessage = "Invalid email address"
                        break
                    case 'auth/user-disabled':
                        errorMessage = "This account has been disabled"
                        break
                    case 'auth/email-already-in-use':
                        errorMessage = "An account with this email already exists"
                        break
                    case 'auth/weak-password':
                        errorMessage = "Password is too weak"
                        break
                    case 'auth/network-request-failed':
                        errorMessage = "Network error. Please check your connection"
                        break
                    case 'auth/too-many-requests':
                        errorMessage = "Too many failed attempts. Please try again later"
                        break
                    default:
                        errorMessage = error.message || "Authentication failed"
                }
            }

            toast.error(errorMessage)
        }
    }

    const isSignIn = type === "sign-in"

    return (
        <div className="card-border lg:min-w-[566px]">
            <div className="flex flex-col gap-6 card py-14 px-10">
                <div className="flex flex-row gap-2 justify-center">
                    <Image src="/logo.svg" alt="logo" width={32} height={38} />
                    <h2 className="text-primary-100">Intrevue</h2>
                </div>
                <h3 className="text-center">Get Interview Ready with AI</h3>
                <Form {...form}>
                    <form
                        onSubmit={form.handleSubmit(onSubmit)}
                        className="w-full space-y-6 mt-4 form"
                    >
                        {!isSignIn && (
                            <FormField
                                control={form.control}
                                name="name"
                                label="Name"
                                placeholder="Enter your name"
                            />
                        )}

                        <FormField
                            control={form.control}
                            name="email"
                            label="Email"
                            placeholder="Enter your email"
                            type="email"
                        />

                        <FormField
                            control={form.control}
                            name="password"
                            label="Password"
                            placeholder="Enter your password"
                            type="password"
                        />

                        <Button className="btn" type="submit">
                            {isSignIn ? "Sign in" : "Create an Account"}
                        </Button>
                    </form>
                </Form>

                <p className="text-center">
                    {isSignIn ? "No account yet?" : "Have an account already?"}
                    <Link
                        href={!isSignIn ? "/sign-in" : "/sign-up"}
                        className="font-bold text-user-primary ml-1"
                    >
                        {!isSignIn ? "Sign in" : "Sign up"}
                    </Link>
                </p>
            </div>
        </div>
    )
}

export default AuthForm