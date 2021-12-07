# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Config for vuln worker.


variable "env" {
  description = "environment name"
  type        = string
}

variable "project" {
  description = "GCP project"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
}

variable "use_profiler" {
  description = "use Stackdriver Profiler"
  type        = bool
}

variable "min_frontend_instances" {
  description = "minimum number of frontend instances"
  type        = number
}


resource "google_cloud_run_service" "worker" {

  lifecycle {
    ignore_changes = [
      # When we deploy, we may use different clients at different versions.
      # Ignore those changes.
      template[0].metadata[0].annotations["run.googleapis.com/client-name"],
      template[0].metadata[0].annotations["run.googleapis.com/client-version"]
    ]
  }

  name     = "${var.env}-vuln-worker"
  project  = var.project
  location = var.region

  template {
    spec {
      containers {
	# Don't hardcode the image here; get it from GCP. See the "data" block
	# below for more.
	image = data.google_cloud_run_service.worker.template[0].spec[0].containers[0].image
        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.project
	}
	env {
	  name = "VULN_WORKER_NAMESPACE"
	  value = var.env
	}
	env {
	  name = "VULN_WORKER_REPORT_ERRORS"
	  value = true
	}
	env {
	  name = "VULN_WORKER_ISSUE_REPO"
	  value = var.env == "dev"? "jba/nested-modules": "golang/vulndb"
	}
	env{
          name  = "VULN_WORKER_USE_PROFILER"
          value = var.use_profiler
        }
        resources {
          limits = {
            "cpu"    = "1000m"
            "memory" = "1Gi"
          }
        }
      }

      service_account_name = "frontend@${var.project}.iam.gserviceaccount.com"
    }

    metadata {
      annotations = {
        "autoscaling.knative.dev/minScale"  = var.min_frontend_instances
        "autoscaling.knative.dev/maxScale"  = "1"
      }
    }
  }
  autogenerate_revision_name = true

  traffic {
    latest_revision = true
    percent         = 100
  }
}

# We deploy new images with gcloud, not terraform, so we need to
# make sure that "terraform apply" doesn't change the deployed image
# to whatever is in this file. (The image attribute is required in
# a Cloud Run config; it can't be empty.)
#
# We use this data source is used to determine the deployed image.
data "google_cloud_run_service" "worker" {
  name     = "${var.env}-vuln-worker"
  project  = var.project
  location = var.region
}
