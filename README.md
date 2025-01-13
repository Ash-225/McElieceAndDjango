## SageMath with Django Live Chat App

## Prerequisites <br>

## Ensure you have Conda installed on your system.<br>

## Python and pip should be available in your environment.
<br>

## #Step 1: Install SageMath

# -You can download and install SageMath using either Conda or pip:

# -Using Conda:
```
conda install -c conda-forge sage
```
## -Using pip:
```
pip install sage
```
## -Step 2: Activate Sage Environment

## -Once SageMath is installed, activate the Sage environment using the following command:
```
conda activate sage
```
<br><br><br>

### #Django Chat Configuration

### #Getting the Files <br>

### #Download the zip file or clone the repository and remove the .git folder:
```
git clone https://github.com/Ash-225/DjangoBase . && rm -rf .git
```
### #Setup

### -Create Virtual Environment

### #Mac:

python3 -m venv venv
source venv/bin/activate

### #Windows:
```
pip install virtualenv 
virtualenv venv 
venv\Scripts\activate.bat 
```
### -Install Dependencies
```
pip install --upgrade pip
pip install -r requirements.txt
```

### -Migrate to Database
```
python manage.py migrate
python manage.py createsuperuser
```

### -Run Application
```
python manage.py runserver
```

### #Generate Secret Key (Important for Deployment)
```
python manage.py shell
from django.core.management.utils import get_random_secret_key
print(get_random_secret_key())
exit()
```
<br><br><br>
### #Running the Application<br>

### #To run the Django live chat application integrated with SageMath, use the following command:
```
python manage.py runserver --noreload
```
### -Database Management

### -The application uses SQLite for managing users and chat groups. You can access and manage the database directly through SQLite.

### #Notes

### Ensure the Sage environment is activated before running the Django application to avoid dependency issues.

### The --noreload flag is used to prevent automatic server reloads, which can interfere with certain SageMath operations.
