# -*- coding: utf-8 -*-
"""
Created on Sun Dec  2 19:31:08 2018

@author: Luisa
"""

from setuptools import setup

setup(
    name = 'client',
    version = '0.1.0',
    packages = ['client'],
    entry_points = {
        'console_scripts': [
            'client = client.__main__:main'
        ]
    })