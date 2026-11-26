<?php

namespace BWH\AuthManager\Services;

use RuntimeException;

/** The off-box audit export will not run as configured; the message is safe to print. */
final class OffboxAuditExportRefused extends RuntimeException {}
