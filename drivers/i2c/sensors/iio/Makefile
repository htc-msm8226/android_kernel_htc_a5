#
# Makefile for the industrial I/O core.
#

obj-$(CONFIG_IIO_ST) += industrialio.o
industrialio-y := industrialio-core.o industrialio-event.o inkern.o
industrialio-$(CONFIG_IIO_BUFFER_ST) += industrialio-buffer.o
industrialio-$(CONFIG_IIO_TRIGGER_ST) += industrialio-trigger.o

obj-$(CONFIG_IIO_TRIGGERED_BUFFER_ST) += industrialio-triggered-buffer.o
obj-$(CONFIG_IIO_KFIFO_BUF_ST) += kfifo_buf.o
