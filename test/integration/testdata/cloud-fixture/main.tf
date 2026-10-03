# What the cloud control's live test scans for, created at the start of each run and destroyed at
# the end, in the empty project draugr-ops keeps for it. Misconfigured on purpose: each resource is
# one a CIS Google Cloud benchmark check fails on, and the test asserts that the check reports it.
# Nothing here holds data or costs money.

terraform {
  required_version = "~> 1.12"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.4"
    }
  }
}

variable "project" {
  description = "The fixture project's ID."
  type        = string
}

variable "run" {
  description = "What makes this run's names its own, such as the workflow run's ID."
  type        = string
}

provider "google" {
  project = var.project
}

# A network with one subnet in us-central1 that keeps no flow logs: compute_subnet_flow_logs_enabled,
# reported for the region, so to the component that claims it.
resource "google_compute_network" "fixture" {
  name                    = "draugr-fixture-${var.run}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "fixture" {
  name          = "draugr-fixture-${var.run}"
  region        = "us-central1"
  network       = google_compute_network.fixture.id
  ip_cidr_range = "10.10.0.0/24"
}

# SSH and RDP open to the whole internet, with no instance behind them: the two firewall checks,
# reported with no region, so to the component that declares the whole account.
resource "google_compute_firewall" "ssh" {
  name          = "draugr-fixture-${var.run}-ssh"
  network       = google_compute_network.fixture.name
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "rdp" {
  name          = "draugr-fixture-${var.run}-rdp"
  network       = google_compute_network.fixture.name
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}
