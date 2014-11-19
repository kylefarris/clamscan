# Changes

This file is a manually maintained list of changes for each release. Feel free
to add your changes here when sending pull requests. Also send corrections if
you spot any mistakes.

### 0.2.1

* ClamAV returns an exit code 1 when it detects a virus but `exec` was interpreting that response as an error. Checking the response with type-sensitive equivalence resolves this bug.

### 0.3 (2014-11-19)

* Corrected the installation instructions for `clamav`. Thank you @jshamley!
* Fixed major bug preventing the `scan_dir` method from working properly
* Corrected documentation describing how to instantiate this module.