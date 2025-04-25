<?php

use App\Http\Controllers\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('/login/google', [AuthController::class, 'loginWithGoogle']);
Route::middleware('auth:api')->post('/logout', [AuthController::class, 'logout']);
