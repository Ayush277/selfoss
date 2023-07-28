export class OfflineStorageNotAvailableError extends Error {
    public name: string;

    constructor(message: string = 'Offline storage is not available') {
        super(message);
        this.name = 'OfflineStorageNotAvailableError';
    }
}

export class TimeoutError extends Error {
    public name: string;

    constructor(message: string) {
        super(message);
        this.name = 'TimeoutError';
    }
}

export class HttpError extends Error {
    public name: string;
    public response: Response;

    constructor(message: string) {
        super(message);
        this.name = 'HttpError';
    }
}

export class LoginError extends Error {
    public name: string;

    constructor(message: string) {
        super(message);
        this.name = 'LoginError';
    }
}

export class UnexpectedStateError extends Error {
    public name: string;

    constructor(message: string) {
        super(message);
        this.name = 'UnexpectedStateError';
    }
}
