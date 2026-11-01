<?php

namespace BWH\AuthManager\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;

/**
 * The one-time code that proves the invited address before an account is created from an
 * application's invitation. Names the application and this service only, like the invitation email,
 * and carries no link: the code is useful only on the invitation's own page.
 */
class InvitationCodeMail extends Mailable
{
    use Queueable;

    public function __construct(
        public readonly string $applicationName,
        #[\SensitiveParameter] public readonly string $code,
        public readonly int $expiresInMinutes,
    ) {}

    public function envelope(): Envelope
    {
        return new Envelope(subject: "Your code to join {$this->applicationName}");
    }

    public function content(): Content
    {
        return new Content(markdown: 'emails.invitation-code', with: [
            'serviceName' => (string) config('app.name'),
        ]);
    }
}
