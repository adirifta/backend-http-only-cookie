<?php

namespace App\Mail;

use App\Models\User;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class VerifyEmail extends Mailable
{
    use Queueable, SerializesModels;

    public $user;
    public $verificationToken;

    public function __construct(User $user, $verificationToken)
    {
        $this->user = $user;
        $this->verificationToken = $verificationToken;
    }

    public function build()
    {
        $verificationUrl = config('app.frontend_url') . '/verify-email/' . $this->verificationToken;

        return $this->subject('Verify Your Email Address')
                    ->view('emails.verify-email')
                    ->with([
                        'user' => $this->user,
                        'verificationUrl' => $verificationUrl
                    ]);
    }
}
