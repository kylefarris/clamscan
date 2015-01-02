# Changes

This file is a manually maintained list of changes for each release. Feel free
to add your changes here when sending pull requests. Also send corrections if
you spot any mistakes.

### 0.2.1

* ClamAV returns an exit code 1 when it detects a virus but `exec` was interpreting that response as an error. Checking the response with type-sensitive equivalence resolves this bug.

### 0.2.2

* Fixed documentation

### 0.4.0 (2014-11-19)

* Corrected the installation instructions for `clamav`. Thank you @jshamley!
* Fixed major bug preventing the `scan_dir` method from working properly
* Corrected documentation describing how to instantiate this module.

### 0.5.0 (2014-12-19)

* Deprecated the `quarantine_path` option. Please only use `quarantine_infected` for now on.
* Updated documentation to reflect above change.

### 0.6.0 (2015-01-02)

__NOTE:__ There are some breaking changes on this release. Since this is still a pre-version 1 release, I decided to only do a minor bump to 0.4.0

* The ability to run "forked" instances of `clamscan` has been removed because of irregularities with different systems--namely if you had `max_forks` set to 3, it would sometimes only scan the first or last file in the group... not good.
* Added the ability to use `clamdscan`. This ultimately negates the downside of removing the forking capability mentioned in item one. This is a really big improvement (many orders of magnitude) if your system has access to the `clamdscan` daemon.
* Added a `file_list` option allowing one to specify a text file that lists (one per line) paths to files to be scanned. This is great if you need to scan hundreds or thousands of random files.
* `clam_path` option has been moved to `clam.path`
* `db` option has been moved to `clam.db`
* `scan_archives` option has been moved to `clam.scan_archives`
* `scan_files` now supports directories as well and will obey your `scan_recursively` option.
