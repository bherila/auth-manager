<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;

/**
 * The invitation email. One plain template whether or not the address has an account here, so the
 * message itself says nothing about the directory. It names the application and this service only:
 * never the inviter, whose display name is free text and would turn the message into a channel.
 */
class AccessInvitationMail extends Mailable
{
    use Queueable;

    public function __construct(
        public readonly string $applicationName,
        #[\SensitiveParameter] public readonly string $link,
        public readonly int $expiresInDays,
    ) {}

    public function envelope(): Envelope
    {
        return new Envelope(subject: "You're invited to {$this->applicationName}");
    }

    public function content(): Content
    {
        return new Content(markdown: 'emails.access-invitation', with: [
            'serviceName' => (string) config('app.name'),
        ]);
    }
}
