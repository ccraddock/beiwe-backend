import calendar
import time
import datetime

from django.utils import timezone
from flask import abort, Blueprint, json, render_template, request, redirect
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import BadRequestKeyError
from werkzeug.utils import secure_filename

from config.constants import ALLOWED_SELFIE_EXTENSIONS, DEVICE_IDENTIFIERS_HEADER
from database.data_access_models import FileToProcess
from database.profiling_models import DecryptionKeyError, UploadTracking
from database.user_models import Participant, Researcher, StudyRelation
from database.study_models import Study
from libs.encryption import decrypt_device_file, DecryptionKeyInvalidError, HandledError
from libs.http_utils import determine_os_api
from libs.logging import log_error
from libs.s3 import get_client_private_key, get_client_public_key_string, s3_upload
from libs.sentry import make_sentry_client
from libs.user_authentication import (authenticate_user, authenticate_user_registration, minimal_validation)

from database.study_models import ParticipantSurvey

################################################################################
############################# GLOBALS... #######################################
################################################################################
external_api = Blueprint('external_api', __name__)


def grab_file_extension(filename):
    """ grabs the chunk of text after the final period. """
    return filename.rsplit('.', 1)[1]


def contains_valid_selfie_extension(filename):
    """ Checks if string has a recognized file extension, this is not necessarily limited to 4 characters. """
    return '.' in filename and grab_file_extension(filename) in ALLOWED_SELFIE_EXTENSIONS

################################################################################
################################ UPLOADS #######################################
################################################################################

# @external_api.route('/loaderio-8ed6e63e16e9e4d07d60a051c4ca6ecb/')
# def temp():
#     from io import StringIO
#     from flask import Response
#     return Response(StringIO(u"loaderio-8ed6e63e16e9e4d07d60a051c4ca6ecb"),
#                     mimetype="txt",
#                     headers={'Content-Disposition':'attachment; filename="loaderio-8ed6e63e16e9e4d07d60a051c4ca6ecb.txt"'})


@external_api.route('/upload_digital_selfie', methods=['POST'])
def upload_digital_selfie():
    """ Entry point to upload GPS, Accelerometer, Audio, PowerState, Calls Log, Texts Log,
    Survey Response, and debugging files to s3.

    Behavior:
    Returns 200 on succesful upload

    A 400 error means there is something is wrong with the uploaded file or its parameters,
    administrators will be emailed regarding this upload, the event will be logged to the apache
    log.  

    If a 500 error occurs that means there is something wrong server side, administrators will be
    emailed and the event will be logged.

    Request format:
    send an http post request to [domain name]/upload, remember to include security
    parameters (see user_authentication for documentation). Provide the contents of the file,
    properly converted to Base64 encoded text, as a request parameter entitled "file".
    Provide the file name in a request parameter entitled "filename". """

    print(f"received {request.values}")


    try:
        patient_id = request.values['beiwe_username'].lower()
        user = Participant.objects.get(patient_id=patient_id)
    except:
        print('user could not be found')
        return abort(403)

    try:
        password = request.values['beiwe_password']
    except:
        print('password was not found')
        return abort(403)

    if not user.debug_validate_password(request.values['beiwe_password']):
        print('password is incorrect')
        return abort(403)

    print('participant verified')

    if 'user_file' not in request.files:
        print('could not find user_file')

    uploaded_file = request.files['user_file']
    filename = secure_filename(uploaded_file.filename)

    print(f'received {filename}')

    if isinstance(uploaded_file, FileStorage):
        print('its a file')
        uploaded_file = uploaded_file.read()
    elif isinstance(uploaded_file, str):
        print('its a string')
        uploaded_file = uploaded_file.encode()
    elif isinstance(uploaded_file, bytes):
        print('its bytes')
        # not current behavior on any app
        pass
    else:
        print('we dont know what it is')
        raise TypeError("uploaded_file was a %s" % type(uploaded_file))

    print('preparing to upload')
    print(contains_valid_selfie_extension(filename))

    filename=f'RAW_DATA/{user.study.object_id}/{user.patient_id}/digital_selfie/{user.patient_id}_{datetime.datetime.now().isoformat()}.{grab_file_extension(filename)}'

    print(f'uploading file to {filename}')

    # print "decryption success:", filename
    # if uploaded data a) actually exists, B) is validly named and typed...
    if uploaded_file and filename and contains_valid_selfie_extension(filename):
        s3_upload(filename, uploaded_file, user.study.object_id, raw_path=True)
        FileToProcess.append_file_for_processing(filename, user.study.object_id, participant=user)
        UploadTracking.objects.create(
            file_path=filename,
            file_size=len(uploaded_file),
            timestamp=timezone.now(),
            participant=user,
        )
        return redirect('https://digitalselfie.ut-wcwh.org/success.html')

    else:
        error_message ="an upload has failed " + patient_id + ", " + filename + ", "
        if not uploaded_file:
            # it appears that occasionally the app creates some spurious files
            # with a name like "rList-org.beiwe.app.LoadingActivity"
            error_message += "there was no/an empty file, returning 200 OK so device deletes bad file."
            log_error(Exception("upload error"), error_message)
            return render_template('blank.html'), 200
        
        elif not filename:
            error_message += "there was no provided file name, this is an app error."
        elif filename and not contains_valid_selfie_extension( filename ):
            error_message += "contains an invalid extension, it was interpretted as "
            error_message += grab_file_extension(filename)
        else:
            error_message += "AN UNKNOWN ERROR OCCURRED."

        tags = {"upload_error": "upload error", "user_id": patient_id}
        print(error_message, tags)
        sentry_client = make_sentry_client('eb', tags)
        sentry_client.captureMessage(error_message)
        
        return redirect('https://digitalselfie.ut-wcwh.org/error.html')