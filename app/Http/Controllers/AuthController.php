<?php

namespace App\Http\Controllers;

use App\Http\Requests\AuthRequest;
use App\Http\Resources\AuthResource;
use Kreait\Firebase\Factory;

use Illuminate\Http\Request;
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
        $factory = (new Factory)
            ->withServiceAccount(base_path(env('FIREBASE_CREDENTIALS')));

        $this->auth = $factory->createAuth();
    }

    public function loginWithGoogle(AuthRequest $request)
    {
        $validated = $request->validated();
        $token = $validated['token'];

        $verifiedIdToken = $this->auth->verifyIdToken($token);
        $firebaseUser = $this->auth->getUser($verifiedIdToken->claims()->get('sub'));

        $user = User::where('email', $firebaseUser->email)->first();

        if (!$user) {
            $user = User::create([
                'name' => $firebaseUser->displayName,
                'email' => $firebaseUser->email,
                'provider_id' => $firebaseUser->uid,
                'password' => Str::random(16),
            ]);
        }

        $tokenResult = $user->accessToken();

        return AuthResource::make([
            'user' => $user,
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => $tokenResult->token->expires_at,
        ]);
    }
    
    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json(['message' => 'Successfully logged out']);
    }
}
