from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("security_monitoring", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="securityevent",
            name="event_type",
            field=models.CharField(default="stored_xss_detected", max_length=64),
        ),
        migrations.AlterField(
            model_name="securityevent",
            name="path",
            field=models.CharField(blank=True, default="/dispatch/", max_length=255),
        ),
        migrations.AlterField(
            model_name="securitylabpayload",
            name="label",
            field=models.CharField(blank=True, default="Stored XSS Vector", max_length=255),
        ),
        migrations.AlterField(
            model_name="securitylabpayload",
            name="endpoint",
            field=models.CharField(blank=True, default="/dispatch/", max_length=255),
        ),
        migrations.AlterField(
            model_name="securitylabpayload",
            name="status",
            field=models.CharField(
                choices=[
                    ("ACTIVE", "Active"),
                    ("QUARANTINED", "Quarantined"),
                    ("REMOVED", "Removed"),
                ],
                default="ACTIVE",
                max_length=32,
            ),
        ),
        migrations.AlterField(
            model_name="ioc",
            name="reputation",
            field=models.CharField(
                choices=[
                    ("MALICIOUS", "Malicious"),
                    ("SUSPICIOUS", "Suspicious"),
                    ("UNKNOWN", "Unknown"),
                    ("CLEAN", "Clean"),
                ],
                default="UNKNOWN",
                max_length=64,
            ),
        ),
        migrations.AlterField(
            model_name="securityincident",
            name="attack_type",
            field=models.CharField(default="Stored XSS", max_length=64),
        ),
    ]
