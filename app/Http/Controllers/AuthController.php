<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Kreait\Firebase\Factory;
use Kreait\Firebase\Auth as FirebaseAuth;
use Kreait\Firebase\Exception\FirebaseException;
use Illuminate\Validation\ValidationException;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    protected $auth;

    public function __construct()
    {
        $firebase = (new Factory)
            ->withServiceAccount([
                'api_key' => env('FIREBASE_API_KEY'),
                'auth_domain' => env('FIREBASE_AUTH_DOMAIN'),
                'project_id' => env('FIREBASE_PROJECT_ID'),
                'storage_bucket' => env('FIREBASE_STORAGE_BUCKET'),
                'messaging_sender_id' => env('FIREBASE_MESSAGING_SENDER_ID'),
                'app_id' => env('FIREBASE_APP_ID'),
            ]);

        $this->auth = $firebase->createAuth();
    }

    public function loginWithGoogle(Request $request)
    {
        try {
            $request->validate([
                'token' => 'required|string',
            ]);

            $token = $request->input('token');

            $verifiedIdToken = $this->auth->verifyIdToken($token);

            $firebaseUser = $this->auth->getUser($verifiedIdToken->claims()->get('sub'));

            $user = User::where('email', $firebaseUser->email)->first();

            if (!$user) {
                $user = User::create([
                    'name' => $firebaseUser->displayName,
                    'email' => $firebaseUser->email,
                    'provider_id' => $firebaseUser->uid,
                    'password' => bcrypt(Str::random(16)),
                ]);
            }

            // Generate Passport token
            $tokenResult = $user->createToken('Personal Access Token');
            $token = $tokenResult->accessToken;

            return response()->json([
                'user' => $user,
                'access_token' => $token,
                'token_type' => 'Bearer',
                'expires_at' => $tokenResult->token->expires_at,
            ]);

        } catch (FirebaseException $e) {
            return response()->json(['error' => 'Invalid token or authentication failed'], 401);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Something went wrong: '.$e->getMessage()], 500);
        }
    }

    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json(['message' => 'Successfully logged out']);
    }
}
