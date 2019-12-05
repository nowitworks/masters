# Scenario demo

## Installation
First run
```
npm install
```
in the ***scenario_demo*** directory.

Then you need to make a link to the [ps-credentials library](../ps-credentials). To do so, run this command (in the ***scenario_demo*** directory)
```
npm link ../ps-credentials/
```
**Note:** You should run this command every time Node complains that `ps-credentials` cannot be found.

Afterwards run
```
gulp
```
in the same directory (if you do not have gulp installed, run `npm install gulp-cli -g`).

You also need to have [docker](https://docs.docker.com/install) and [docker-compose](https://docs.docker.com/compose/install/) installed.

## Usage

### Set up Moodle

Follow the instructions [here](../moodle-lti-test-demo/readme.md) to set up Moodle.

**TODO** write all the steps here

High level steps:
- Login with admin account (user: `user`, pass: `bitnami`)
- Create a course
- Enroll admin in the course as instructor
- Create another user
- Enroll user as student in the course
- Edit course page to add LTI tool for issuing credentials
- Edit course page to add URL for questionnaire
- Log out, and log in as the student
- Have fun!



### Install and run MongoDB

**TODO**: Instructions on how to start DB service
 - https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/#install-mongodb-community-edition-using-deb-packages


### Run servers

Open 4 terminal windows, and open directories *moodle*, *issuer*, *tool*, and *cred*. In each one of them run `node server.js`.

Now open http://127.0.0.1:3000/ in your browser and you can try the demo.
