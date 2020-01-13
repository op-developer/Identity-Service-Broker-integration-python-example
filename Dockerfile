FROM kennethreitz/pipenv
ENV PORT '3045'

WORKDIR /app
CMD python3 sp.py
EXPOSE 3045