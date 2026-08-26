<?php

return [
    /*
    | The provider row is retained while relying applications reconcile. A
    | scheduled purge removes it sooner when every expected application has
    | acknowledged, or at this deadline while naming any missing applications.
    */
    'retention_days' => (int) env('IDENTITY_TOMBSTONE_RETENTION_DAYS', 30),
];
