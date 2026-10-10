<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\Mail;
use ReflectionProperty;
use RuntimeException;
use Symfony\Component\Mailer\Bridge\Brevo\Transport\BrevoApiTransport;
use Symfony\Component\Mailer\Transport\FailoverTransport;
use Symfony\Component\Mailer\Transport\RoundRobinTransport;
use Symfony\Component\Mailer\Transport\Smtp\SmtpTransport;
use Tests\TestCase;

/** The `brevo` and `hybrid` mailers. Neither is the default; MAIL_MAILER chooses. */
class BrevoMailerTest extends TestCase
{
    public function test_the_brevo_mailer_builds_the_api_transport_from_the_dsn(): void
    {
        config(['services.brevo.dsn' => 'brevo+api://synthetic-key@default']);

        $this->assertInstanceOf(BrevoApiTransport::class, Mail::mailer('brevo')->getSymfonyTransport());
    }

    public function test_the_hybrid_mailer_fails_over_from_brevo_to_smtp(): void
    {
        config(['services.brevo.dsn' => 'brevo+api://synthetic-key@default']);

        $transport = Mail::mailer('hybrid')->getSymfonyTransport();

        $this->assertInstanceOf(FailoverTransport::class, $transport);
        $children = (new ReflectionProperty(RoundRobinTransport::class, 'transports'))->getValue($transport);
        $this->assertCount(2, $children);
        $this->assertInstanceOf(BrevoApiTransport::class, $children[0]);
        $this->assertInstanceOf(SmtpTransport::class, $children[1]);
    }

    public function test_the_brevo_mailer_refuses_to_build_without_a_dsn(): void
    {
        config(['services.brevo.dsn' => null]);

        $this->expectException(RuntimeException::class);

        Mail::mailer('brevo')->getSymfonyTransport();
    }
}
